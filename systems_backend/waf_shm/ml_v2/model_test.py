import joblib
import numpy as np
import pandas as pd
import re
from scipy.stats import entropy
from scipy.sparse import hstack

# 1. Load Preprocessors
vectorizer = joblib.load('tfidf_vectorizer.pkl')
scaler = joblib.load('standard_scaler.pkl')

def calculate_scipy_entropy(text):
    if not text or not isinstance(text, str): return 0
    probs = pd.Series(list(text)).value_counts() / len(text)
    return entropy(probs, base=2)

def special_char_ratio(text):
    if not text or not isinstance(text, str): return 0
    return len(re.findall(r'[^a-zA-Z0-9]', text)) / len(text)

# 2. The Teammate's exact test string
test_string = "http://localhost:8080/tienda1/publico/entrar.jsp HTTP/1.1errorMsg=..."

# 3. Extract Features
length = len(test_string)
ent = calculate_scipy_entropy(test_string)
ratio = special_char_ratio(test_string)

num_features = np.array([[length, ent, ratio]])
num_scaled = scaler.transform(num_features)
tfidf_features = vectorizer.transform([test_string])

final_features = hstack([num_scaled, tfidf_features])
input_data = final_features.toarray().astype(np.float32)[0]

# 4. Print the exact array for C++ comparison
print("=== VERIFIED ONNX INPUT ARRAY ===")
print("String:", test_string)
print("\nExpected First 10 Values (Numericals + First 7 TF-IDF nodes):")
for i in range(10):
    if i == 0: print(f"Index {i} (Scaled Length) : {input_data[i]:.6f}")
    elif i == 1: print(f"Index {i} (Scaled Entropy): {input_data[i]:.6f}")
    elif i == 2: print(f"Index {i} (Scaled Ratio)  : {input_data[i]:.6f}")
    else: print(f"Index {i} (TF-IDF Node {i-3}): {input_data[i]:.6f}")