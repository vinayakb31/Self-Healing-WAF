import os
import sqlite3
import sys


SECURITY_DIR = os.path.join(os.path.dirname(__file__), "security_automation")
sys.path.append(SECURITY_DIR)

from diagnosis_agent import RULES, classify_attack, save_rule

try:
    from classifier import detect_with_regex
except Exception:
    detect_with_regex = None


def classify_with_fallback(payload):
    """Use the teammate LLM first, then their local regex classifier."""
    attack_type = classify_attack(payload)
    if attack_type != "Unknown":
        return attack_type, "LLM"

    if detect_with_regex:
        regex_result = detect_with_regex(payload)
        if regex_result:
            return regex_result, "local regex fallback"

    return "Unknown", "manual review"


def save_rule_once(attack_type):
    expected = f"{attack_type} | {RULES[attack_type]}"
    rules_path = os.path.join(SECURITY_DIR, "generated_rules.txt")

    if os.path.exists(rules_path):
        with open(rules_path, "r") as file:
            if expected in {line.strip() for line in file if line.strip()}:
                return False

    original_dir = os.getcwd()
    os.chdir(SECURITY_DIR)
    save_rule(attack_type)
    os.chdir(original_dir)
    return True


def run_bridge():
    db_path = "waf_quarantine.db"
    if not os.path.exists(db_path):
        print(f"Database {db_path} not found.")
        return

    print("=== Self-Healing WAF: Quarantine Bridge ===")
    print("Connecting to Quarantine DB to review PENDING requests...\n")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, request_payload FROM blocked_requests WHERE status = 'PENDING'")
    pending_requests = cursor.fetchall()

    if not pending_requests:
        print("No PENDING requests found in the quarantine database.")
        print("To test this script, insert a PENDING row into waf_quarantine.db.")
        conn.close()
        return

    print(f"Found {len(pending_requests)} pending request(s). Handing off to diagnosis logic...\n")

    for req_id, payload in pending_requests:
        print(f"Reviewing Request ID {req_id}:")
        print(f"  Payload: {payload[:100]}...")

        attack_type, source = classify_with_fallback(payload)

        if attack_type.lower() == "normal":
            new_status = "VERIFIED_NORMAL"
            print(f"  Diagnosis: Normal Traffic via {source}")
        elif attack_type in RULES:
            new_status = "VERIFIED_ATTACK"
            print(f"  Diagnosis: Verified Attack ({attack_type}) via {source}")

            if save_rule_once(attack_type):
                print(f"  Rule saved for {attack_type}")
            else:
                print(f"  Rule already existed for {attack_type}")
        else:
            new_status = "REVIEW_REQUIRED"
            print("  Diagnosis: Unknown. Marking REVIEW_REQUIRED for human/LLM review.")

        if new_status != "PENDING":
            cursor.execute("UPDATE blocked_requests SET status = ? WHERE id = ?", (new_status, req_id))
            print(f"  Database updated: {new_status}")

        print("-" * 60)

    conn.commit()
    conn.close()

    print("\nBridge execution completed.")
    print("Verified rows are now available for retrain_brain.py.")


def inject_test_data():
    """Helper function to inject mock PENDING requests for testing purposes."""
    conn = sqlite3.connect("waf_quarantine.db")
    cursor = conn.cursor()

    cursor.execute("SELECT count(*) FROM blocked_requests WHERE status = 'PENDING'")
    if cursor.fetchone()[0] == 0:
        print("Injecting sample PENDING requests for testing...")
        mock_logs = [
            (
                "2026-05-02T12:00:00",
                "192.168.1.100",
                "http://localhost:8080/tienda1/publico/entrar.jsp?user=' OR 1=1 --",
                0.95,
                "PENDING",
            ),
            (
                "2026-05-02T12:05:00",
                "192.168.1.101",
                "http://localhost:8080/tienda1/publico/carrito.jsp?checkout=true",
                0.88,
                "PENDING",
            ),
            (
                "2026-05-02T12:10:00",
                "192.168.1.102",
                "http://localhost:8080/tienda1/app?q=<script>alert('XSS')</script>",
                0.91,
                "PENDING",
            ),
        ]
        cursor.executemany(
            """
            INSERT INTO blocked_requests
                (timestamp, ip_address, request_payload, ai_confidence_score, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            mock_logs,
        )
        conn.commit()

    conn.close()


if __name__ == "__main__":
    if "--inject-test-data" in sys.argv:
        inject_test_data()
    run_bridge()
