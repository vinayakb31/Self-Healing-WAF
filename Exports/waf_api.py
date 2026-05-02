import joblib
import numpy as np
import pandas as pd
import re
import onnxruntime as rt
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from scipy.stats import entropy
from scipy.sparse import hstack
from contextlib import asynccontextmanager

# --- 1. Feature Extraction Functions ---
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

# --- 2. Global State & Startup ---
ml_assets = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Initializing WAF Brain...")
    ml_assets['vectorizer'] = joblib.load('tfidf_vectorizer.pkl')
    ml_assets['scaler'] = joblib.load('standard_scaler.pkl')
    ml_assets['sess'] = rt.InferenceSession("waf_brain_v1.onnx", providers=['CPUExecutionProvider'])
    ml_assets['input_name'] = ml_assets['sess'].get_inputs()[0].name
    ml_assets['label_name'] = ml_assets['sess'].get_outputs()[0].name
    ml_assets['prob_name'] = ml_assets['sess'].get_outputs()[1].name
    print("WAF API is armed and listening.")
    yield
    ml_assets.clear()

app = FastAPI(title="WAF Inference API", lifespan=lifespan)

# --- 3. Request Schema ---
class TrafficPayload(BaseModel):
    request_string: str

# --- 4. The Inference Endpoint ---
@app.post("/predict")
async def analyze_traffic(payload: TrafficPayload):
    raw_request = payload.request_string
    if not raw_request:
        raise HTTPException(status_code=400, detail="Request string cannot be empty")

    try:
        # Extract features
        length = len(raw_request)
        ent = calculate_scipy_entropy(raw_request)
        sql_kws = sql_keyword_count(raw_request)
        digits = digit_ratio(raw_request)
        upper = uppercase_ratio(raw_request)

        # Structure as DataFrame to match Scaler expectations silently
        num_df = pd.DataFrame([{
            'length': length,
            'entropy': ent,
            'sql_kw_count': sql_kws,
            'digit_ratio': digits,
            'uppercase_ratio': upper
        }])

        # Vectorize and combine
        num_scaled = ml_assets['scaler'].transform(num_df)
        tfidf_features = ml_assets['vectorizer'].transform([raw_request])
        
        final_features = hstack([num_scaled, tfidf_features])
        input_data = final_features.toarray().astype(np.float32)

        # Execute ONNX Inference
        label_output, prob_output = ml_assets['sess'].run(
            [ml_assets['label_name'], ml_assets['prob_name']], 
            {ml_assets['input_name']: input_data}
        )
        
        predicted_class = int(label_output[0])
        confidence_dict = prob_output[0]
        confidence_score = float(confidence_dict.get(predicted_class, 0))

        return {
            "status": "success",
            "prediction": "ANOMALOUS" if predicted_class == 1 else "NORMAL",
            "threat_level": predicted_class,
            "confidence": round(confidence_score * 100, 2),
            "features_extracted": {
                "length": length,
                "entropy": round(ent, 4),
                "sql_keywords": sql_kws
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference pipeline failed: {str(e)}")