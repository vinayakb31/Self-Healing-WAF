import sysv_ipc
import struct
import time
import json
import re
import math
from urllib.parse import unquote_plus
import numpy as np
import onnxruntime as ort

# ── keys ──────────────────────────────────────────────────────────
SHM_KEY     = 0x1234
SEM_KEY     = 0x5678
MQ_KEY      = 0x9ABC
BUFFER_SIZE = 10

# -- shared memory layout -------------------------------------------------
SLOT_FORMAT   = 'i i 16s 256s 4096s'
SLOT_SIZE     = struct.calcsize(SLOT_FORMAT)
HEADER_FORMAT = 'i i i i'
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)

# ── load model + configs ──────────────────────────────────────────
session    = ort.InferenceSession("waf_brain_v1.onnx")
input_name = session.get_inputs()[0].name

with open("tfidf_config.json") as f:
    tfidf_config = json.load(f)

with open("scaler_config.json") as f:
    scaler = json.load(f)
    mean   = np.array(scaler["mean"])
    scale  = np.array(scaler["scale"])

vocab       = tfidf_config["vocabulary"]        # char n-gram → index
idf_weights = np.array(tfidf_config["idf"])
max_features = tfidf_config["max_features"]     # 1000
ngram_range  = tfidf_config["ngram_range"]      # [1, 3]

print(f"Model loaded!")
print(f"Vocab size: {len(vocab)}, Max features: {max_features}")
print(f"N-gram range: {ngram_range}")
print(f"Expected input size: 3 numeric + {max_features} tfidf = {3 + max_features}\n")

session.run(None, {input_name: np.zeros((1, 3 + max_features), dtype=np.float32)})
print("Inference warm-up complete.\n")


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


def has_attack_signature(uri, body):
    decoded = unquote_plus(f"{uri} {body or ''}")
    return any(re.search(pattern, decoded) for pattern in ATTACK_PATTERNS)


def looks_suspicious(uri, body):
    decoded = unquote_plus(f"{uri} {body or ''}")
    suspicious_chars = len(re.findall(r"['\"`;<>${}()=]", decoded))
    return suspicious_chars >= 3 or has_attack_signature(uri, body)

# ── feature extraction (mirrors training pipeline exactly) ────────
def extract_features(uri, body):
    # Step 1: combine uri + body (treat missing body as empty string)
    body = body if body else ""
    text = "http://localhost:8080" + uri + " HTTP/1.1" + body  # combined string — same as training

    # Step 2: three numeric features on combined string
    length = len(text)

    # Shannon entropy (base 2)
    if length > 0:
        freq    = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        entropy = -sum((v/length) * math.log2(v/length) for v in freq.values())
    else:
        entropy = 0.0

    # Special char ratio: non-alphanumeric / total length
    special_count = len(re.findall(r'[^a-zA-Z0-9]', text))
    special_ratio = special_count / length if length > 0 else 0.0

    # Step 3: scale numeric features using scaler_config
    numeric_raw    = np.array([length, entropy, special_ratio])
    numeric_scaled = (numeric_raw - mean) / scale

    # Step 4: character-level TF-IDF (ngrams 1-3)
    ngram_min, ngram_max = ngram_range[0], ngram_range[1]
    tfidf_vec = np.zeros(max_features)

    # generate all character n-grams
    total_ngrams = 0
    ngram_counts = {}
    for n in range(ngram_min, ngram_max + 1):
        for i in range(len(text) - n + 1):
            ngram = text[i:i+n]
            if ngram in vocab:
                idx = vocab[ngram]
                if idx < max_features:
                    ngram_counts[idx] = ngram_counts.get(idx, 0) + 1
                    total_ngrams += 1

    # apply TF-IDF
    if total_ngrams > 0:
        for idx, count in ngram_counts.items():
            tf = count / total_ngrams
            tfidf_vec[idx] = tf * idf_weights[idx]

    # Step 5: concatenate — numeric FIRST, then tfidf (order matters!)
    features = np.concatenate([numeric_scaled, tfidf_vec]).astype(np.float32)
    return features  # shape: (1003,)

# ── connect IPC ───────────────────────────────────────────────────
shm = sysv_ipc.SharedMemory(SHM_KEY)
sem = sysv_ipc.Semaphore(SEM_KEY)
mq  = sysv_ipc.MessageQueue(MQ_KEY, sysv_ipc.IPC_CREAT)

print("Connected to shared memory + message queue! Waiting for requests...\n")

# ── main loop ─────────────────────────────────────────────────────
while True:
    processed = False

    sem.acquire()
    try:
        header_raw = shm.read(HEADER_SIZE, 0)
        write_pos, read_pos, count, next_request_id = struct.unpack(HEADER_FORMAT, header_raw)

        if count > 0:
            offset   = HEADER_SIZE + (read_pos * SLOT_SIZE)
            slot_raw = shm.read(SLOT_SIZE, offset)
            ready, request_id, method, uri, body = struct.unpack(SLOT_FORMAT, slot_raw)

            method = method.decode('utf-8', errors='replace').rstrip('\x00')
            uri    = uri.decode('utf-8', errors='replace').rstrip('\x00')
            body   = body.decode('utf-8', errors='replace').rstrip('\x00')

            # advance read pointer
            new_read_pos = (read_pos + 1) % BUFFER_SIZE
            new_count    = count - 1
            shm.write(struct.pack(HEADER_FORMAT, write_pos, new_read_pos,
                                  new_count, next_request_id), 0)
            processed = True
        else:
            ready = 0
    finally:
        sem.release()

    if processed and ready == 1:
        # run inference
        features = extract_features(uri, body).reshape(1, -1)
        result   = session.run(None, {input_name: features})

        # handle both [prob] and [[prob_0, prob_1]] output shapes
        out = result[0]
        if out.ndim == 2:
            score = float(out[0][1])   # probability of class 1 (attack)
        else:
            score = float(out[0])

        signature_hit = has_attack_signature(uri, body)
        verdict = "DENY" if signature_hit or (score > 0.98 and looks_suspicious(uri, body)) else "ALLOW"

        label = "🚨 BLOCK" if verdict == "DENY" else "✅ ALLOW"
        print(f"[{label}] id={request_id} {method} {uri}")
        print(f"         Body   : {body[:60]}")
        print(f"         Score  : {score:.4f}")
        print(f"         Rule   : {'signature/model' if signature_hit else 'model'}")
        print()

        # Send verdict to the specific Nginx worker waiting on this request ID.
        msg = verdict.encode('utf-8').ljust(16, b'\x00')
        mq.send(msg, True, type=request_id)

    if not processed:
        time.sleep(0.001)
