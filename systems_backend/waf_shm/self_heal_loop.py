import os
import sqlite3
import subprocess
import sys
import time


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(BASE_DIR, "ml_v2")
DB_PATH = os.path.join(ML_DIR, "waf_quarantine.db")
BRIDGE_PATH = os.path.join(ML_DIR, "bridge_quarantine.py")
INTERVAL_SECONDS = 5


def pending_count():
    if not os.path.exists(DB_PATH):
        return 0

    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM blocked_requests WHERE status = 'PENDING'"
        ).fetchone()
        return int(row[0] if row else 0)
    finally:
        conn.close()


print("Self-healing loop started.")
print(f"Watching quarantine DB: {DB_PATH}")
print(f"Bridge: {BRIDGE_PATH}")

while True:
    try:
        count = pending_count()
        if count > 0:
            print(f"Found {count} pending quarantined request(s). Running bridge...")
            result = subprocess.run(
                [sys.executable, BRIDGE_PATH],
                cwd=ML_DIR,
                text=True,
                capture_output=True,
                timeout=120,
            )
            if result.stdout.strip():
                print(result.stdout.strip())
            if result.stderr.strip():
                print(result.stderr.strip())
            if result.returncode != 0:
                print(f"Bridge exited with status {result.returncode}")
    except Exception as exc:
        print(f"Self-healing loop error: {exc}")

    time.sleep(INTERVAL_SECONDS)
