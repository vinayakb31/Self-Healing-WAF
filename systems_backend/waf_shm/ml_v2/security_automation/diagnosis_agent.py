import requests

# -------------------------------
# CONFIG
# -------------------------------
MODEL = "phi"

# -------------------------------
# FINAL TRUSTED RULES (LOCKED)
# -------------------------------
RULES = {
    "SQL Injection": r"('|\").*(OR|AND).*=.*",
    "XSS": r"<script.*?>.*?</script>",
    "Log4j": r"\$\{jndi:.*\}",
    "Command Injection": r"(;|\|\||&&)\s*\w+"
}

# -------------------------------
# Read Logs
# -------------------------------
def read_anomalies():
    try:
        with open("anomalies.log", "r") as file:
            return [line.strip() for line in file if line.strip()]
    except:
        return []

# -------------------------------
# AI Classification ONLY
# -------------------------------
def classify_attack(log_entry):
    prompt = f"""
    Identify attack type from:
    SQL Injection, XSS, Command Injection, Log4j, Normal.

    Respond ONLY with the name.

    Log:
    {log_entry}
    """

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=60
        )

        data = response.json()

        if "response" not in data:
            return "Unknown"

        result = data["response"].strip()

        for key in RULES:
            if key.lower() in result.lower():
                return key

        return "Unknown"

    except:
        return "Unknown"

# -------------------------------
# Save Clean Rule
# -------------------------------
def save_rule(attack_type):
    try:
        with open("generated_rules.txt", "a") as file:
            file.write(f"{attack_type} | {RULES[attack_type]}\n")
    except:
        pass

# -------------------------------
# MAIN SYSTEM
# -------------------------------
def run_agent():
    logs = read_anomalies()

    if not logs:
        print("No logs found.")
        return

    print("🛡️ Clean Self-Healing System Running...\n")

    for log in logs:
        print(f"Log: {log}")

        attack = classify_attack(log)
        print(f"Detected: {attack}")

        if attack in RULES:
            print(f"Applied Rule: {RULES[attack]}")
            save_rule(attack)
        else:
            print("Skipped")

        print("-" * 50)

# -------------------------------
# RUN
# -------------------------------
if __name__ == "__main__":
    run_agent()