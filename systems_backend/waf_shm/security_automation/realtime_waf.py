import re
from datetime import datetime

# -------------------------------
# Load Rules
# -------------------------------
def load_rules():
    rules = []

    try:
        with open("generated_rules.txt", "r") as file:
            for line in file:
                if "|" in line:
                    attack, pattern = line.strip().split("|", 1)
                    rules.append((attack.strip(), pattern.strip()))
    except:
        print("No rules found.")

    return rules

# -------------------------------
# Log Requests (IMPORTANT)
# -------------------------------
def log_request(request, result, attack_type=None):
    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open("waf_logs.txt", "a") as file:
        if attack_type:
            file.write(f"{time} | BLOCKED | {attack_type} | {request}\n")
        else:
            file.write(f"{time} | ALLOWED | {request}\n")

# -------------------------------
# Check Request
# -------------------------------
def check_request(request, rules):
    for attack, pattern in rules:
        try:
            if re.search(pattern, request, re.IGNORECASE):
                return attack, pattern
        except:
            continue
    return None, None

# -------------------------------
# Real-Time Loop
# -------------------------------
def run_waf():
    rules = load_rules()

    if not rules:
        print("⚠️ No rules loaded.")
        return

    print("🛡️ Real-Time WAF Started (type 'exit' to stop)\n")

    while True:
        user_input = input("Enter Request: ")

        if user_input.lower() == "exit":
            break

        attack, pattern = check_request(user_input, rules)

        if attack:
            print(f"🚫 BLOCKED → {attack}")
            print(f"🔎 Matched Pattern: {pattern}")
            log_request(user_input, "BLOCKED", attack)
        else:
            print("✅ ALLOWED")
            log_request(user_input, "ALLOWED")

        print("-" * 50)

# -------------------------------
# Run
# -------------------------------
if __name__ == "__main__":
    run_waf()