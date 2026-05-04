import sqlite3
import os
import sys

# Add teammate's folder to path so we can reuse their LLM logic directly
sys.path.append(os.path.join(os.path.dirname(__file__), 'security_automation'))
from diagnosis_agent import classify_attack, save_rule

def run_bridge():
    db_path = "waf_quarantine.db"
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} not found.")
        return

    print("=== Self-Healing WAF: Quarantine Bridge ===")
    print("Connecting to Quarantine DB to review PENDING requests...\n")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Find pending requests (those blocked by the C++ interceptor or API awaiting review)
    cursor.execute("SELECT id, request_payload FROM blocked_requests WHERE status = 'PENDING'")
    pending_requests = cursor.fetchall()

    if not pending_requests:
        print("No PENDING requests found in the quarantine database.")
        print("   (To test this script, insert a PENDING row into waf_quarantine.db)")
        conn.close()
        return

    print(f"Found {len(pending_requests)} pending request(s). Handing off to Security Team's LLM Diagnosis Agent...\n")

    for req_id, payload in pending_requests:
        print(f"Reviewing Request ID {req_id}:\n  Payload: {payload[:100]}...")
        
        # 1. Call the teammate's Ollama LLM classification function
        attack_type = classify_attack(payload)
        
        new_status = ""
        if attack_type.lower() == "normal":
            new_status = "VERIFIED_NORMAL"
            print(f"  ➔ LLM Diagnosis: Normal Traffic (False Positive)")
            
        elif attack_type != "Unknown":
            new_status = "VERIFIED_ATTACK"
            print(f"  ➔ LLM Diagnosis: Verified Attack ({attack_type})")
            
            # 2. Trigger the teammate's rule generation to update regex defenses
            print(f"  ➔ Generating and saving regex rule for {attack_type}...")
            # We change dir temporarily so their script saves the rule in their folder
            original_dir = os.getcwd()
            os.chdir('security_automation')
            save_rule(attack_type)
            os.chdir(original_dir)
            
        else:
            new_status = "PENDING" # Leave for manual human review
            print(f"  ➔ LLM Diagnosis: Unknown. Leaving as PENDING for human review.")

        # 3. Close the loop: Update the database so your `retrain_brain.py` can see it
        if new_status != "PENDING":
            cursor.execute("UPDATE blocked_requests SET status = ? WHERE id = ?", (new_status, req_id))
            print(f"  ➔ Database updated: {new_status}")
            
        print("-" * 60)

    conn.commit()
    conn.close()
    
    print("\nBridge execution completed.")
    print("   The AI/MLE Retrain Pipeline (retrain_brain.py) can now pick up the newly verified logs to self-heal the ONNX model.")

def inject_test_data():
    """Helper function to inject mock PENDING requests for testing purposes."""
    conn = sqlite3.connect("waf_quarantine.db")
    cursor = conn.cursor()
    
    # Check if we already have pending requests to avoid duplicates
    cursor.execute("SELECT count(*) FROM blocked_requests WHERE status = 'PENDING'")
    if cursor.fetchone()[0] == 0:
        print("Injecting sample PENDING requests for testing...")
        mock_logs = [
            ("2026-05-02T12:00:00", "192.168.1.100", "http://localhost:8080/tienda1/publico/entrar.jsp?user=' OR 1=1 --", 0.95, "PENDING"),
            ("2026-05-02T12:05:00", "192.168.1.101", "http://localhost:8080/tienda1/publico/carrito.jsp?checkout=true", 0.88, "PENDING"), # This is the false positive our ML model had
            ("2026-05-02T12:10:00", "192.168.1.102", "http://localhost:8080/tienda1/app?q=<script>alert('XSS')</script>", 0.91, "PENDING")
        ]
        cursor.executemany('''
            INSERT INTO blocked_requests (timestamp, ip_address, request_payload, ai_confidence_score, status)
            VALUES (?, ?, ?, ?, ?)
        ''', mock_logs)
        conn.commit()
    conn.close()

if __name__ == "__main__":
    inject_test_data()
    run_bridge()
