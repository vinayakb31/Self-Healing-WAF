import sqlite3
import pandas as pd
import numpy as np
import joblib
import re
from scipy.stats import entropy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from scipy.sparse import hstack
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

print("=== WAF Self-Healing Pipeline Initiated ===")

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

# --- 2. Extract Verified Logs from Database ---
print("Fetching newly verified threat intelligence...")
conn = sqlite3.connect("waf_quarantine.db")
query = "SELECT request_payload, status FROM blocked_requests WHERE status IN ('VERIFIED_NORMAL', 'VERIFIED_ATTACK')"
new_data_df = pd.read_sql_query(query, conn)
conn.close()

if new_data_df.empty:
    print("No new verified logs found. Model is up to date. Exiting.")
    exit()

# Map the text statuses to integer labels
new_data_df['Type'] = np.where(new_data_df['status'] == 'VERIFIED_ATTACK', 1, 0)
new_data_df.rename(columns={'request_payload': 'full_request'}, inplace=True)
new_data_df.drop(columns=['status'], inplace=True)

print(f"Found {len(new_data_df)} new verified records. Injecting into baseline dataset...")

# --- 3. Merge with Foundation Dataset ---
# Load your original CSIC dataset (ensure this CSV is in the same folder)
baseline_df = pd.read_csv('csic_database.csv')
majority_class = baseline_df['classification'].value_counts().idxmax()
baseline_df['Type'] = np.where(baseline_df['classification'] == majority_class, 0, 1)
baseline_df['full_request'] = baseline_df['URL'].fillna('') + baseline_df['content'].fillna('')
baseline_df = baseline_df[['full_request', 'Type']]

# Combine the old and new data
# We "oversample" the new data (repeat it 50x) so the model learns the correction immediately
boosted_new_data = pd.concat([new_data_df] * 50, ignore_index=True)
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
print("Exporting upgraded assets...")
joblib.dump(vectorizer, 'tfidf_vectorizer_v2.pkl')
joblib.dump(scaler, 'standard_scaler_v2.pkl')

feature_count = X_final.shape[1]
initial_type = [('float_input', FloatTensorType([None, feature_count]))]
onnx_model = convert_sklearn(model, initial_types=initial_type)

with open("waf_brain_v2.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print("\nSuccess! System is healed. Hand off 'waf_brain_v2.onnx' to your Systems Lead for hot-swapping.")