import joblib
import numpy as np
import pandas as pd
import re
import sqlite3
import time
import onnxruntime as rt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from scipy.stats import entropy
from scipy.sparse import hstack
from contextlib import asynccontextmanager
from datetime import datetime

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
    ml_assets['vectorizer'] = joblib.load('tfidf_vectorizer_v2.pkl')
    ml_assets['scaler'] = joblib.load('standard_scaler_v2.pkl')
    ml_assets['sess'] = rt.InferenceSession("waf_brain_v2.onnx", providers=['CPUExecutionProvider'])
    ml_assets['input_name'] = ml_assets['sess'].get_inputs()[0].name
    ml_assets['label_name'] = ml_assets['sess'].get_outputs()[0].name
    ml_assets['prob_name'] = ml_assets['sess'].get_outputs()[1].name

    # Initialize shadow log database
    init_shadow_db()

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


# --- 4. Request Schema ---
class TrafficPayload(BaseModel):
    request_string: str


# --- 5. Health Check Endpoint ---
@app.get("/health")
async def health_check():
    """Returns the operational status of the WAF engine."""
    model_loaded = 'sess' in ml_assets
    return {
        "status": "operational" if model_loaded else "degraded",
        "model_version": "v2.0",
        "model_loaded": model_loaded,
        "feature_count": ml_assets['sess'].get_inputs()[0].shape[1] if model_loaded else None,
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
            "features_extracted": features_meta
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

        input_data, features_meta = extract_features(
            raw_request, ml_assets['vectorizer'], ml_assets['scaler']
        )
        predicted_class, confidence_score = run_inference(
            input_data, ml_assets['sess'],
            ml_assets['input_name'], ml_assets['label_name'], ml_assets['prob_name']
        )

        latency_ms = (time.perf_counter() - start_time) * 1000

        prediction_label = "ANOMALOUS" if predicted_class == 1 else "NORMAL"

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
            "note": "This request was NOT blocked. Shadow mode logs predictions for validation."
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