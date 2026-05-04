import joblib
import numpy as np
import os
import pandas as pd
import re
import sqlite3
import time
import onnxruntime as rt
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from scipy.stats import entropy
from scipy.sparse import hstack
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import urlparse, unquote_plus

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Self-Healing WAF — Inference API v2.0                         ║
# ║  Updated to load v2 model, preprocessors, and shadow mode      ║
# ╚══════════════════════════════════════════════════════════════════╝

# --- 1. Feature Extraction Functions (must match retrain_brain.py exactly) ---
def calculate_scipy_entropy(text: str) -> float:
    if not text: return 0.0
    probs = pd.Series(list(text)).value_counts() / len(text)
    return float(entropy(probs, base=2))

def sql_keyword_count(text: str) -> int:
    if not text: return 0
    pattern = r'\b(SELECT|UNION|DROP|INSERT|UPDATE|DELETE|OR|AND|FROM|WHERE|EXEC|CAST|CHAR|DECLARE)\b'
    return len(re.findall(pattern, text, re.IGNORECASE))

def digit_ratio(text: str) -> float:
    if not text: return 0.0
    return sum(c.isdigit() for c in text) / len(text)

def uppercase_ratio(text: str) -> float:
    if not text: return 0.0
    letters = [c for c in text if c.isalpha()]
    if not letters: return 0.0
    return sum(c.isupper() for c in letters) / len(letters)

def extract_features(raw_request: str, vectorizer, scaler):
    """Extract and combine all features into the ONNX-ready input array."""
    length = len(raw_request)
    ent = calculate_scipy_entropy(raw_request)
    sql_kws = sql_keyword_count(raw_request)
    digits = digit_ratio(raw_request)
    upper = uppercase_ratio(raw_request)

    num_df = pd.DataFrame([{
        'length': length,
        'entropy': ent,
        'sql_kw_count': sql_kws,
        'digit_ratio': digits,
        'uppercase_ratio': upper
    }])

    num_scaled = scaler.transform(num_df)
    tfidf_features = vectorizer.transform([raw_request])
    final_features = hstack([num_scaled, tfidf_features])
    input_data = final_features.toarray().astype(np.float32)

    features_meta = {
        "length": length,
        "entropy": round(ent, 4),
        "sql_keywords": sql_kws,
        "digit_ratio": round(digits, 4),
        "uppercase_ratio": round(upper, 4)
    }
    return input_data, features_meta

def run_inference(input_data, sess, input_name, label_name, prob_name):
    """Execute ONNX inference and return prediction + confidence."""
    label_output, prob_output = sess.run(
        [label_name, prob_name],
        {input_name: input_data}
    )
    predicted_class = int(label_output[0])
    confidence_dict = prob_output[0]
    confidence_score = float(confidence_dict.get(predicted_class, 0))
    return predicted_class, confidence_score


# --- Fast Guardrails & Feedback Helpers ---
MODEL_ARTIFACTS = (
    "tfidf_vectorizer_v2.pkl",
    "standard_scaler_v2.pkl",
    "waf_brain_v2.onnx",
)

ATTACK_PATTERNS = [
    r"(?i)(?:^|[^a-z])or[^a-z]+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"(?i)union\s+select",
    r"(?i)drop\s+table",
    r"(?i)insert\s+into",
    r"(?i)<\s*script",
    r"(?i)\$\{\s*jndi\s*:",
    r"(?i)(?:\.\./|%2e%2e%2f)",
    r"(?i)/etc/passwd",
]

STATIC_ASSET_EXTENSIONS = {
    ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".png", ".svg",
    ".webp", ".woff", ".woff2",
}


def artifact_mtimes():
    return {
        path: os.path.getmtime(path) if os.path.exists(path) else None
        for path in MODEL_ARTIFACTS
    }


def load_ml_assets():
    """Load or reload model artifacts as one coherent asset set."""
    vectorizer = joblib.load("tfidf_vectorizer_v2.pkl")
    scaler = joblib.load("standard_scaler_v2.pkl")
    sess = rt.InferenceSession("waf_brain_v2.onnx", providers=["CPUExecutionProvider"])

    ml_assets.clear()
    ml_assets.update({
        "vectorizer": vectorizer,
        "scaler": scaler,
        "sess": sess,
        "input_name": sess.get_inputs()[0].name,
        "label_name": sess.get_outputs()[0].name,
        "prob_name": sess.get_outputs()[1].name,
        "artifact_mtimes": artifact_mtimes(),
        "loaded_at": datetime.now().isoformat(),
    })


def maybe_reload_ml_assets():
    if "artifact_mtimes" not in ml_assets:
        load_ml_assets()
        return

    current = artifact_mtimes()
    if current != ml_assets["artifact_mtimes"]:
        load_ml_assets()


def has_attack_signature(raw_request: str) -> bool:
    decoded = unquote_plus(raw_request or "")
    return any(re.search(pattern, decoded) for pattern in ATTACK_PATTERNS)


def looks_suspicious(raw_request: str) -> bool:
    decoded = unquote_plus(raw_request or "")
    suspicious_chars = len(re.findall(r"['\"`;<>${}()=]", decoded))
    return suspicious_chars >= 3 or has_attack_signature(decoded)


def extract_url_path(raw_request: str) -> str:
    first_line = (raw_request or "").splitlines()[0].strip()
    parts = first_line.split()
    candidate = parts[1] if len(parts) >= 2 and parts[0].isalpha() else parts[0] if parts else ""
    parsed = urlparse(candidate)
    return parsed.path or candidate


def is_probably_benign_static_asset(raw_request: str) -> bool:
    if has_attack_signature(raw_request) or looks_suspicious(raw_request):
        return False

    path = extract_url_path(raw_request).lower()
    return any(path.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)


def fast_waf_decision(raw_request: str):
    if has_attack_signature(raw_request):
        return {
            "prediction": "ANOMALOUS",
            "threat_level": 1,
            "confidence": 100.0,
            "decision_source": "signature_guardrail",
        }

    if is_probably_benign_static_asset(raw_request):
        return {
            "prediction": "NORMAL",
            "threat_level": 0,
            "confidence": 100.0,
            "decision_source": "static_asset_guardrail",
        }

    return None


def init_quarantine_db():
    conn = sqlite3.connect("waf_quarantine.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            request_payload TEXT,
            ai_confidence_score REAL,
            status TEXT
        )
    ''')
    conn.commit()
    conn.close()


def log_quarantine_feedback(request_payload, confidence, status):
    conn = sqlite3.connect("waf_quarantine.db")
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id FROM blocked_requests
        WHERE request_payload = ? AND status IN ('PENDING', 'VERIFIED_NORMAL', 'VERIFIED_ATTACK', 'TRAINED_NORMAL', 'TRAINED_ATTACK')
        LIMIT 1
        """,
        (request_payload[:2000],),
    )
    if cursor.fetchone():
        conn.close()
        return False

    cursor.execute('''
        INSERT INTO blocked_requests (timestamp, ip_address, request_payload, ai_confidence_score, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        "127.0.0.1",
        request_payload[:2000],
        float(confidence),
        status,
    ))
    conn.commit()
    conn.close()
    return True


# --- 2. Shadow Mode Logger ---
def init_shadow_db():
    """Create the shadow log database if it doesn't exist."""
    conn = sqlite3.connect("shadow_log.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shadow_predictions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            request_payload TEXT,
            prediction TEXT,
            confidence REAL,
            features_json TEXT,
            inference_latency_ms REAL
        )
    ''')
    conn.commit()
    conn.close()

def log_shadow_prediction(request_payload, prediction, confidence, features, latency_ms):
    """Log a shadow-mode prediction to the database."""
    import json
    conn = sqlite3.connect("shadow_log.db")
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO shadow_predictions (timestamp, request_payload, prediction, confidence, features_json, inference_latency_ms)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        datetime.now().isoformat(),
        request_payload[:2000],  # Truncate very long payloads
        prediction,
        confidence,
        json.dumps(features),
        latency_ms
    ))
    conn.commit()
    conn.close()


# --- 3. Global State & Startup ---
ml_assets = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("  Self-Healing WAF — Inference Engine v2.0")
    print("=" * 60)
    print("\nInitializing WAF Brain (v2 assets)...")

    # Load v2 preprocessors and model
    load_ml_assets()

    # Initialize shadow log database
    init_shadow_db()
    init_quarantine_db()

    print("WAF API v2.0 is armed and listening.")
    print(f"  Model: waf_brain_v2.onnx")
    print(f"  Features: 5 numeric + 1000 TF-IDF = {ml_assets['sess'].get_inputs()[0].shape[1]} total")
    print(f"  Shadow DB: shadow_log.db\n")
    yield
    ml_assets.clear()

app = FastAPI(
    title="Self-Healing WAF API",
    description="AI-powered Web Application Firewall with shadow mode and self-healing capabilities",
    version="2.0.0",
    lifespan=lifespan
)

# Mount the static directory for the dashboard UI
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


# --- 4. Request Schema ---
class TrafficPayload(BaseModel):
    request_string: str


# --- 5. Health Check Endpoint ---
@app.get("/health")
async def health_check():
    """Returns the operational status of the WAF engine."""
    if 'sess' in ml_assets:
        maybe_reload_ml_assets()
    model_loaded = 'sess' in ml_assets
    return {
        "status": "operational" if model_loaded else "degraded",
        "model_version": "v2.0",
        "model_loaded": model_loaded,
        "feature_count": ml_assets['sess'].get_inputs()[0].shape[1] if model_loaded else None,
        "loaded_at": ml_assets.get("loaded_at"),
        "timestamp": datetime.now().isoformat()
    }


# --- 6. The Inference Endpoint (ENFORCEMENT MODE) ---
@app.post("/predict")
async def analyze_traffic(payload: TrafficPayload):
    """
    Analyze incoming traffic and return a verdict.
    This is the ENFORCEMENT endpoint — it returns BLOCK/ALLOW decisions.
    """
    raw_request = payload.request_string
    if not raw_request:
        raise HTTPException(status_code=400, detail="Request string cannot be empty")

    try:
        start_time = time.perf_counter()
        maybe_reload_ml_assets()

        guardrail = fast_waf_decision(raw_request)
        if guardrail:
            latency_ms = (time.perf_counter() - start_time) * 1000
            return {
                "status": "success",
                **guardrail,
                "latency_ms": round(latency_ms, 2),
                "features_extracted": {"guardrail": guardrail["decision_source"]}
            }

        input_data, features_meta = extract_features(
            raw_request, ml_assets['vectorizer'], ml_assets['scaler']
        )
        predicted_class, confidence_score = run_inference(
            input_data, ml_assets['sess'],
            ml_assets['input_name'], ml_assets['label_name'], ml_assets['prob_name']
        )

        latency_ms = (time.perf_counter() - start_time) * 1000

        return {
            "status": "success",
            "prediction": "ANOMALOUS" if predicted_class == 1 else "NORMAL",
            "threat_level": predicted_class,
            "confidence": round(confidence_score * 100, 2),
            "latency_ms": round(latency_ms, 2),
            "features_extracted": features_meta,
            "decision_source": "ml_model"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference pipeline failed: {str(e)}")


# --- 7. Shadow Mode Endpoint (OBSERVATION ONLY — NO BLOCKING) ---
@app.post("/shadow")
async def shadow_analyze(payload: TrafficPayload):
    """
    Shadow Mode: Run inference and LOG the result, but NEVER block traffic.
    Use this to validate model accuracy against real production traffic
    before switching to enforcement mode.
    """
    raw_request = payload.request_string
    if not raw_request:
        raise HTTPException(status_code=400, detail="Request string cannot be empty")

    try:
        start_time = time.perf_counter()
        maybe_reload_ml_assets()

        input_data, features_meta = extract_features(
            raw_request, ml_assets['vectorizer'], ml_assets['scaler']
        )
        predicted_class, confidence_score = run_inference(
            input_data, ml_assets['sess'],
            ml_assets['input_name'], ml_assets['label_name'], ml_assets['prob_name']
        )

        latency_ms = (time.perf_counter() - start_time) * 1000

        model_prediction_label = "ANOMALOUS" if predicted_class == 1 else "NORMAL"
        model_confidence_percent = round(confidence_score * 100, 2)
        prediction_label = model_prediction_label
        guardrail = fast_waf_decision(raw_request)
        quarantine_status = None

        if guardrail and guardrail["threat_level"] == 0:
            if predicted_class == 1:
                log_quarantine_feedback(
                    request_payload=raw_request,
                    confidence=confidence_score,
                    status="VERIFIED_NORMAL",
                )
                quarantine_status = "VERIFIED_NORMAL"
            prediction_label = guardrail["prediction"]
            predicted_class = guardrail["threat_level"]
            confidence_score = guardrail["confidence"] / 100.0
            features_meta = {
                **features_meta,
                "guardrail": guardrail["decision_source"],
                "model_prediction": model_prediction_label,
                "model_confidence": model_confidence_percent,
            }
        elif guardrail and guardrail["threat_level"] == 1:
            prediction_label = guardrail["prediction"]
            predicted_class = guardrail["threat_level"]
            confidence_score = guardrail["confidence"] / 100.0
            features_meta = {
                **features_meta,
                "guardrail": guardrail["decision_source"],
            }
        elif prediction_label == "ANOMALOUS":
            if log_quarantine_feedback(
                request_payload=raw_request,
                confidence=confidence_score,
                status="PENDING",
            ):
                quarantine_status = "PENDING"

        # Log to shadow database (non-blocking observation)
        log_shadow_prediction(
            request_payload=raw_request,
            prediction=prediction_label,
            confidence=round(confidence_score * 100, 2),
            features=features_meta,
            latency_ms=round(latency_ms, 2)
        )

        return {
            "status": "logged",
            "mode": "shadow",
            "action": "ALLOW (shadow mode — observation only)",
            "prediction": prediction_label,
            "threat_level": predicted_class,
            "confidence": round(confidence_score * 100, 2),
            "latency_ms": round(latency_ms, 2),
            "features_extracted": features_meta,
            "decision_source": features_meta.get("guardrail", "ml_model"),
            "quarantine_status": quarantine_status,
            "note": "This request was NOT blocked. Shadow mode logs predictions and queues model feedback when needed."
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Shadow inference failed: {str(e)}")


# --- 8. Shadow Log Stats Endpoint ---
@app.get("/shadow/stats")
async def shadow_stats():
    """Return aggregate statistics from shadow mode predictions."""
    try:
        conn = sqlite3.connect("shadow_log.db")
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM shadow_predictions")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM shadow_predictions WHERE prediction = 'ANOMALOUS'")
        anomalous = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(confidence) FROM shadow_predictions")
        avg_confidence = cursor.fetchone()[0]

        cursor.execute("SELECT AVG(inference_latency_ms) FROM shadow_predictions")
        avg_latency = cursor.fetchone()[0]

        conn.close()

        return {
            "total_predictions": total,
            "anomalous_count": anomalous,
            "normal_count": total - anomalous,
            "anomaly_rate": round((anomalous / total * 100), 2) if total > 0 else 0,
            "avg_confidence": round(avg_confidence, 2) if avg_confidence else 0,
            "avg_latency_ms": round(avg_latency, 2) if avg_latency else 0
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read shadow stats: {str(e)}")

# --- 9. Dashboard UI Route ---
@app.get("/", response_class=HTMLResponse)
async def dashboard_ui():
    """Serve the Real-Time Monitoring Dashboard."""
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()

# --- 10. Dashboard API: Combined Metrics ---
@app.get("/dashboard/metrics")
async def dashboard_metrics():
    """Return metrics for the dashboard."""
    try:
        conn = sqlite3.connect("shadow_log.db")
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM shadow_predictions")
        total_shadow = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM shadow_predictions WHERE prediction = 'ANOMALOUS'")
        anomalous_shadow = cur.fetchone()[0]
        cur.execute("SELECT AVG(inference_latency_ms) FROM shadow_predictions")
        avg_latency = cur.fetchone()[0]
        conn.close()

        pending_count = 0
        healed_count = 0
        if os.path.exists("waf_quarantine.db"):
            conn_q = sqlite3.connect("waf_quarantine.db")
            cur_q = conn_q.cursor()
            cur_q.execute("SELECT COUNT(*) FROM blocked_requests WHERE status = 'PENDING'")
            pending_count = cur_q.fetchone()[0]
            cur_q.execute("SELECT COUNT(*) FROM blocked_requests WHERE status IN ('VERIFIED_ATTACK', 'VERIFIED_NORMAL', 'TRAINED_ATTACK', 'TRAINED_NORMAL')")
            healed_count = cur_q.fetchone()[0]
            conn_q.close()

        return {
            "total_requests": total_shadow,
            "blocked_requests": anomalous_shadow,
            "block_rate": round((anomalous_shadow / total_shadow * 100), 2) if total_shadow > 0 else 0,
            "avg_latency_ms": round(avg_latency, 2) if avg_latency else 0,
            "pending_reviews": pending_count,
            "healed_rules": healed_count
        }
    except Exception as e:
        return {"error": str(e)}

# --- 11. Dashboard API: Recent Logs ---
@app.get("/dashboard/logs")
async def dashboard_logs():
    """Return the latest requests from shadow log and quarantine db."""
    try:
        logs = []
        conn = sqlite3.connect("shadow_log.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT * FROM shadow_predictions ORDER BY timestamp DESC LIMIT 20")
        for row in cur.fetchall():
            logs.append({
                "source": "Shadow Mode",
                "id": row["id"],
                "timestamp": row["timestamp"],
                "payload": row["request_payload"],
                "prediction": row["prediction"],
                "confidence": row["confidence"],
                "latency_ms": row["inference_latency_ms"],
                "status": "LOGGED"
            })
        conn.close()

        if os.path.exists("waf_quarantine.db"):
            conn_q = sqlite3.connect("waf_quarantine.db")
            conn_q.row_factory = sqlite3.Row
            cur_q = conn_q.cursor()
            cur_q.execute("SELECT * FROM blocked_requests ORDER BY timestamp DESC LIMIT 20")
            for row in cur_q.fetchall():
                logs.append({
                    "source": "Interceptor",
                    "id": row["id"],
                    "timestamp": row["timestamp"],
                    "payload": row["request_payload"],
                    "prediction": "ANOMALOUS",
                    "confidence": round(row["ai_confidence_score"] * 100, 2) if row["ai_confidence_score"] else 0,
                    "latency_ms": "-",
                    "status": row["status"]
                })
            conn_q.close()

        # Sort combined logs by timestamp descending and take top 30
        logs.sort(key=lambda x: x["timestamp"], reverse=True)
        return {"logs": logs[:30]}
    except Exception as e:
        return {"error": str(e)}
