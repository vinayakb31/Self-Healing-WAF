import re
from urllib.parse import unquote_plus, urlparse


ATTACK_PATTERNS = [
    ("SQL Injection", r"(?i)(?:^|[^a-z])or[^a-z]+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"),
    ("SQL Injection", r"(?i)union\s+select"),
    ("SQL Injection", r"(?i)drop\s+table"),
    ("SQL Injection", r"(?i)insert\s+into"),
    ("XSS", r"(?i)<\s*script"),
    ("Log4j", r"(?i)\$\{\s*jndi\s*:"),
    ("Path Traversal", r"(?i)(?:\.\./|%2e%2e%2f)"),
    ("Path Traversal", r"(?i)/etc/passwd"),
]

STATIC_ASSET_EXTENSIONS = {
    ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".png", ".svg",
    ".webp", ".woff", ".woff2",
}


def clamp(value, low=0, high=100):
    return max(low, min(high, value))


def extract_url_path(raw_request):
    first_line = (raw_request or "").splitlines()[0].strip()
    parts = first_line.split()
    candidate = parts[1] if len(parts) >= 2 and parts[0].isalpha() else parts[0] if parts else ""
    parsed = urlparse(candidate)
    return parsed.path or candidate


def attack_matches(raw_request):
    decoded = unquote_plus(raw_request or "")
    matches = []
    for attack_type, pattern in ATTACK_PATTERNS:
        if re.search(pattern, decoded):
            matches.append(attack_type)
    return sorted(set(matches))


def looks_like_static_asset(raw_request):
    path = extract_url_path(raw_request).lower()
    return any(path.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)


def suspicious_character_count(raw_request):
    decoded = unquote_plus(raw_request or "")
    return len(re.findall(r"['\"`;<>${}()=]", decoded))


def assess_risk(raw_request, features, model_prediction, model_confidence):
    """
    Combine deterministic WAF signals and model output into a deployable decision.

    The model is one risk signal. It is not allowed to be the sole source of truth.
    """
    features = features or {}
    score = 0
    signals = []

    def add(source, points, reason):
        nonlocal score
        score += points
        signals.append({"source": source, "points": points, "reason": reason})

    matched_attacks = attack_matches(raw_request)
    if matched_attacks:
        add("signature", 90, "Matched known attack pattern: " + ", ".join(matched_attacks))

    if looks_like_static_asset(raw_request) and not matched_attacks:
        add("request_shape", -35, "Static asset path with no attack signature")

    suspicious_chars = suspicious_character_count(raw_request)
    if suspicious_chars >= 3:
        add("request_shape", min(25, suspicious_chars * 3), f"{suspicious_chars} suspicious metacharacters")

    sql_keywords = int(features.get("sql_keywords", 0) or 0)
    if sql_keywords:
        add("features", min(30, sql_keywords * 10), f"{sql_keywords} SQL keyword(s)")

    entropy = float(features.get("entropy", 0) or 0)
    if entropy >= 5.3 and len(raw_request or "") > 25:
        add("features", 8, f"High character entropy: {entropy:.2f}")

    if len(raw_request or "") < 8:
        add("request_shape", 15, "Very short or malformed request string")

    model_points = int(round(model_confidence * 40))
    if model_prediction == 1:
        add("ml_model", model_points, f"Model predicted anomalous at {model_confidence * 100:.2f}%")
    else:
        add("ml_model", -int(round(model_confidence * 25)), f"Model predicted normal at {model_confidence * 100:.2f}%")

    risk_score = clamp(score)

    if risk_score >= 80:
        action = "BLOCK"
        prediction = "ANOMALOUS"
        threat_level = 1
    elif risk_score >= 60:
        action = "CHALLENGE"
        prediction = "ANOMALOUS"
        threat_level = 1
    elif risk_score >= 30:
        action = "LOG"
        prediction = "NORMAL"
        threat_level = 0
    else:
        action = "ALLOW"
        prediction = "NORMAL"
        threat_level = 0

    return {
        "risk_score": risk_score,
        "action": action,
        "prediction": prediction,
        "threat_level": threat_level,
        "confidence": float(risk_score),
        "signals": signals,
        "model_prediction": "ANOMALOUS" if model_prediction == 1 else "NORMAL",
        "model_confidence": round(model_confidence * 100, 2),
    }
