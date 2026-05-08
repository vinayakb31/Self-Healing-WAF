import os
import sqlite3
import subprocess
import sys
import time


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "..", "waf_quarantine.db")
BRIDGE_PATH = os.path.join(BASE_DIR, "bridge_quarantine.py")
RETRAIN_PATH = os.path.join(BASE_DIR, "retrain_brain.py")
INTERVAL_SECONDS = 5


def status_count(statuses):
    if not os.path.exists(DB_PATH):
        return 0

    conn = sqlite3.connect(DB_PATH)
    try:
        placeholders = ",".join("?" for _ in statuses)
        row = conn.execute(
            f"SELECT COUNT(*) FROM blocked_requests WHERE status IN ({placeholders})",
            tuple(statuses),
        ).fetchone()
        return int(row[0] if row else 0)
    finally:
        conn.close()


def run_step(label, script_path):
    result = subprocess.run(
        [sys.executable, script_path],
        cwd=BASE_DIR,
        text=True,
        capture_output=True,
        timeout=300,
    )
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    if result.returncode != 0:
        print(f"{label} exited with status {result.returncode}")
    return result.returncode == 0


print("Self-healing loop started.")
print(f"Watching quarantine DB: {DB_PATH}")
print(f"Bridge: {BRIDGE_PATH}")
print(f"Retrain: {RETRAIN_PATH}")

while True:
    try:
        pending = status_count(["PENDING"])
        if pending > 0:
            print(f"Found {pending} pending quarantined request(s). Running bridge...")
            run_step("Bridge", BRIDGE_PATH)

        trainable = status_count(["VERIFIED_NORMAL", "VERIFIED_ATTACK"])
        if trainable > 0:
            print(f"Found {trainable} verified request(s). Running retrain...")
            run_step("Retrain", RETRAIN_PATH)
    except Exception as exc:
        print(f"Self-healing loop error: {exc}")

    time.sleep(INTERVAL_SECONDS)
