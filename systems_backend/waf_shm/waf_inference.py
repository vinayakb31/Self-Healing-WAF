import json
import math
import os
import re
import sqlite3
import struct
import threading
import time
from datetime import datetime
from urllib.parse import unquote_plus

import numpy as np
import onnxruntime as ort
import sysv_ipc

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_V2_DIR = os.path.join(BASE_DIR, "ml_v2")
DYNAMIC_RULE_FILES = [
    os.path.join(ML_V2_DIR, "security_automation", "generated_rules.txt"),
    os.path.join(BASE_DIR, "security_automation", "generated_rules.txt"),
    os.path.join(BASE_DIR, "generated_rules.txt"),
]
RULE_RELOAD_INTERVAL = 2.0

SHM_KEY = 0x1234
SEM_KEY = 0x5678
MQ_KEY = 0x9ABC
BUFFER_SIZE = 10

HEADER_FORMAT = "i i i i"
SLOT_FORMAT = "i i 16s 256s 4096s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
SLOT_SIZE = struct.calcsize(SLOT_FORMAT)

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


def decode_field(raw):
    return raw.decode("utf-8", errors="replace").rstrip("\x00")


def build_request_string(method, uri, body):
    body = body if body and body != "no body" else ""
    return f"{method} http://localhost:8080{uri} HTTP/1.1\n{unquote_plus(body)}"


def has_attack_signature(uri, body):
    decoded = unquote_plus(f"{uri} {body or ''}")
    return any(re.search(pattern, decoded) for pattern in ATTACK_PATTERNS)


def looks_suspicious(uri, body):
    decoded = unquote_plus(f"{uri} {body or ''}")
    suspicious_chars = len(re.findall(r"['\"`;<>${}()=]", decoded))
    return suspicious_chars >= 3 or has_attack_signature(uri, body)


def calculate_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class DynamicRules:
    def __init__(self, paths):
        self.paths = paths
        self._mtimes = {}
        self._rules = []
        self._lock = threading.Lock()
        self.reload(force=True)
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def _watch_loop(self):
        while True:
            try:
                self.reload()
            except Exception as exc:
                print(f"Dynamic rule reload error: {exc}")
            time.sleep(RULE_RELOAD_INTERVAL)

    def reload(self, force=False):
        changed = force
        current_mtimes = {}

        for path in self.paths:
            try:
                current_mtimes[path] = os.path.getmtime(path)
            except FileNotFoundError:
                current_mtimes[path] = None

        if current_mtimes != self._mtimes:
            changed = True

        if not changed:
            return

        compiled = []
        for path in self.paths:
            if not os.path.exists(path):
                continue

            with open(path, "r", encoding="utf-8", errors="replace") as file:
                for line_no, line in enumerate(file, start=1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "|" in line:
                        name, pattern = [part.strip() for part in line.split("|", 1)]
                    else:
                        name, pattern = f"{os.path.basename(path)}:{line_no}", line

                    try:
                        compiled.append((name, re.compile(pattern, re.IGNORECASE), path))
                    except re.error as exc:
                        print(f"Skipping invalid dynamic rule {path}:{line_no}: {exc}")

        with self._lock:
            self._rules = compiled
            self._mtimes = current_mtimes

        print(f"Dynamic rules loaded: {len(self._rules)}")

    def match(self, raw_request):
        decoded = unquote_plus(raw_request or "")
        with self._lock:
            rules = list(self._rules)

        for name, pattern, _path in rules:
            if pattern.search(decoded):
                return name

        return None


def fast_verdict(method, uri, body, dynamic_rules=None):
    """Cheap guardrail before ML: let boring traffic pass, block clear signatures."""
    raw_request = build_request_string(method, uri, body)

    if has_attack_signature(uri, body):
        return "DENY", 1.0, raw_request, "signature"

    if dynamic_rules:
        dynamic_rule = dynamic_rules.match(raw_request)
        if dynamic_rule:
            return "DENY", 1.0, raw_request, f"dynamic_rule:{dynamic_rule}"

    if not looks_suspicious(uri, body):
        return "ALLOW", 1.0, raw_request, "fast"

    return None, 0.0, raw_request, "ml"


class V2Brain:
    def __init__(self):
        import joblib
        import pandas as pd
        from scipy.sparse import hstack

        self.pd = pd
        self.hstack = hstack
        self.vectorizer = joblib.load(os.path.join(ML_V2_DIR, "tfidf_vectorizer_v2.pkl"))
        self.scaler = joblib.load(os.path.join(ML_V2_DIR, "standard_scaler_v2.pkl"))
        self.session = ort.InferenceSession(
            os.path.join(ML_V2_DIR, "waf_brain_v2.onnx"),
            providers=["CPUExecutionProvider"],
        )
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [output.name for output in self.session.get_outputs()]
        feature_count = self.session.get_inputs()[0].shape[1]
        self.session.run(None, {self.input_name: np.zeros((1, feature_count), dtype=np.float32)})
        self.feature_count = feature_count

    def extract(self, raw_request):
        length = len(raw_request)
        entropy = calculate_entropy(raw_request)
        sql_keywords = len(
            re.findall(
                r"\b(SELECT|UNION|DROP|INSERT|UPDATE|DELETE|OR|AND|FROM|WHERE|EXEC|CAST|CHAR|DECLARE)\b",
                raw_request,
                re.IGNORECASE,
            )
        )
        digit_ratio = sum(c.isdigit() for c in raw_request) / length if length else 0.0
        letters = [c for c in raw_request if c.isalpha()]
        uppercase_ratio = (
            sum(c.isupper() for c in letters) / len(letters) if letters else 0.0
        )

        num_df = self.pd.DataFrame(
            [
                {
                    "length": length,
                    "entropy": entropy,
                    "sql_kw_count": sql_keywords,
                    "digit_ratio": digit_ratio,
                    "uppercase_ratio": uppercase_ratio,
                }
            ]
        )
        num_scaled = self.scaler.transform(num_df)
        tfidf = self.vectorizer.transform([raw_request])
        return self.hstack([num_scaled, tfidf]).toarray().astype(np.float32)

    def predict(self, method, uri, body):
        raw_request = build_request_string(method, uri, body)
        features = self.extract(raw_request)
        outputs = self.session.run(None, {self.input_name: features})

        label = int(outputs[0][0])
        confidence = 0.0
        if len(outputs) > 1:
            probs = outputs[1][0]
            if isinstance(probs, dict):
                confidence = float(probs.get(label, 0.0))
            else:
                arr = np.asarray(probs)
                if arr.ndim > 0 and label < arr.shape[-1]:
                    confidence = float(arr[label])

        return label, confidence, raw_request


class V1Brain:
    def __init__(self):
        self.session = ort.InferenceSession(os.path.join(BASE_DIR, "waf_brain_v1.onnx"))
        self.input_name = self.session.get_inputs()[0].name
        with open(os.path.join(BASE_DIR, "tfidf_config.json")) as f:
            self.tfidf_config = json.load(f)
        with open(os.path.join(BASE_DIR, "scaler_config.json")) as f:
            scaler = json.load(f)
        self.mean = np.array(scaler["mean"])
        self.scale = np.array(scaler["scale"])
        self.vocab = self.tfidf_config["vocabulary"]
        self.idf_weights = np.array(self.tfidf_config["idf"])
        self.max_features = self.tfidf_config["max_features"]
        self.ngram_range = self.tfidf_config["ngram_range"]
        self.session.run(
            None,
            {self.input_name: np.zeros((1, 3 + self.max_features), dtype=np.float32)},
        )

    def extract(self, method, uri, body):
        text = build_request_string(method, uri, body)
        length = len(text)
        entropy = calculate_entropy(text)
        special_count = len(re.findall(r"[^a-zA-Z0-9]", text))
        special_ratio = special_count / length if length else 0.0
        numeric_scaled = (np.array([length, entropy, special_ratio]) - self.mean) / self.scale

        tfidf_vec = np.zeros(self.max_features)
        total_ngrams = 0
        ngram_counts = {}
        for n in range(self.ngram_range[0], self.ngram_range[1] + 1):
            for i in range(len(text) - n + 1):
                ngram = text[i : i + n]
                if ngram in self.vocab:
                    idx = self.vocab[ngram]
                    if idx < self.max_features:
                        ngram_counts[idx] = ngram_counts.get(idx, 0) + 1
                        total_ngrams += 1

        if total_ngrams:
            for idx, count in ngram_counts.items():
                tfidf_vec[idx] = (count / total_ngrams) * self.idf_weights[idx]

        return np.concatenate([numeric_scaled, tfidf_vec]).astype(np.float32), text

    def predict(self, method, uri, body):
        features, raw_request = self.extract(method, uri, body)
        result = self.session.run(None, {self.input_name: features.reshape(1, -1)})
        out = result[0]
        score = float(out[0][1]) if getattr(out, "ndim", 1) == 2 else float(out[0])
        return int(score > 0.5), score, raw_request


def load_brain():
    try:
        brain = V2Brain()
        print(f"ML v2 brain loaded from {ML_V2_DIR}")
        print(f"Expected input size: {brain.feature_count}")
        return brain, "v2"
    except Exception as exc:
        print(f"ML v2 unavailable, falling back to v1: {exc}")
        return V1Brain(), "v1"


def init_quarantine_db():
    db_path = os.path.join(ML_V2_DIR, "waf_quarantine.db")
    os.makedirs(ML_V2_DIR, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            request_payload TEXT,
            ai_confidence_score REAL,
            status TEXT
        )
        """
    )
    conn.commit()
    conn.close()
    return db_path


def log_quarantine(db_path, raw_request, confidence):
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        INSERT INTO blocked_requests
            (timestamp, ip_address, request_payload, ai_confidence_score, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            datetime.now().isoformat(),
            "127.0.0.1",
            raw_request[:2000],
            float(confidence),
            "PENDING",
        ),
    )
    conn.commit()
    conn.close()


brain, brain_version = load_brain()
quarantine_db = init_quarantine_db()
dynamic_rules = DynamicRules(DYNAMIC_RULE_FILES)

shm = sysv_ipc.SharedMemory(SHM_KEY)
sem = sysv_ipc.Semaphore(SEM_KEY)
mq = sysv_ipc.MessageQueue(MQ_KEY, sysv_ipc.IPC_CREAT)

print("Inference warm-up complete.")
print(f"Quarantine DB: {quarantine_db}")
print("Connected to shared memory + message queue! Waiting for requests...\n")

while True:
    processed = False
    payload = None

    sem.acquire()
    try:
        header_raw = shm.read(HEADER_SIZE, 0)
        write_pos, read_pos, count, next_request_id = struct.unpack(
            HEADER_FORMAT, header_raw
        )

        if count > 0:
            offset = HEADER_SIZE + (read_pos * SLOT_SIZE)
            slot_raw = shm.read(SLOT_SIZE, offset)
            ready, request_id, method, uri, body = struct.unpack(SLOT_FORMAT, slot_raw)
            method = decode_field(method)
            uri = decode_field(uri)
            body = decode_field(body)
            new_read_pos = (read_pos + 1) % BUFFER_SIZE
            new_count = count - 1
            shm.write(
                struct.pack(
                    HEADER_FORMAT,
                    write_pos,
                    new_read_pos,
                    new_count,
                    next_request_id,
                ),
                0,
            )
            processed = True
            payload = (ready, request_id, method, uri, body)
    finally:
        sem.release()

    if payload and payload[0] == 1:
        _, request_id, method, uri, body = payload
        start = time.perf_counter()

        verdict, confidence, raw_request, decision_source = fast_verdict(
            method, uri, body, dynamic_rules
        )

        if verdict is None:
            label, confidence, raw_request = brain.predict(method, uri, body)

            signature_hit = has_attack_signature(uri, body)
            deny_by_model = label == 1 and looks_suspicious(uri, body)
            verdict = "DENY" if signature_hit or deny_by_model else "ALLOW"
            decision_source = brain_version

        latency_ms = (time.perf_counter() - start) * 1000

        if verdict == "DENY":
            log_quarantine(quarantine_db, raw_request, confidence)

        print(
            f"[{'BLOCK' if verdict == 'DENY' else 'ALLOW'}] "
            f"id={request_id} model={decision_source} score={confidence:.4f} "
            f"latency={latency_ms:.3f}ms {method} {uri}"
        )
        print(f"         Body: {body[:80]}")
        print()

        msg = verdict.encode("utf-8").ljust(16, b"\x00")
        mq.send(msg, True, type=request_id)

    if not processed:
        time.sleep(0.001)
