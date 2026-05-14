import pandas as pd
import random
import os
import re

# Paths and configuration
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "juice_shop_attacks.csv")
TOTAL_SAMPLES = 20000  # Number of samples to generate

# Modern Juice Shop paths
NORMAL_PATHS = [
    "/api/Users/login",
    "/rest/products/search?q=",
    "/api/Feedbacks",
    "/rest/admin/application-configuration",
    "/api/BasketItems",
    "/api/Cards",
    "/api/Addresss",
    "/assets/public/images/products/",
    "/main-es2015.js",
    "/polyfills-es2015.js",
    "/styles.css",
]

# Attack Payloads
SQLI_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT NULL,NULL,NULL --",
    "admin' --",
    "')) OR 1=1 --",
    "'; DROP TABLE Users; --",
]

NOSQLI_PAYLOADS = [
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "this.password.length > 0"}',
    '{"$regex": ".*"}',
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<iframe src=\"javascript:alert(`xss`)\">",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.domain)",
    "';alert(1);'",
]

BANNED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/.env",
    "/config/database.js",
    "/package.json",
]

def augment_url(url, payload):
    # Randomly choose how to inject the payload
    if "?" in url:
        return url + payload
    return url + "/" + payload

def generate_juice_data():
    print(f"Generating {TOTAL_SAMPLES} Juice Shop synthetic records...")
    rows = []

    for _ in range(TOTAL_SAMPLES // 2):
        # Generate Normal Traffic
        path = random.choice(NORMAL_PATHS)
        if "search" in path or "login" in path:
            path += str(random.randint(1, 1000))
        rows.append({"payload": path, "is_attack": 0})

        # Generate Attacks
        attack_type = random.choice(["sqli", "nosqli", "xss", "lfi"])
        base_path = random.choice(NORMAL_PATHS)
        
        if attack_type == "sqli":
            payload = random.choice(SQLI_PAYLOADS)
        elif attack_type == "nosqli":
            payload = random.choice(NOSQLI_PAYLOADS)
        elif attack_type == "xss":
            payload = random.choice(XSS_PAYLOADS)
        else:
            payload = random.choice(BANNED_FILES)
            base_path = "/assets/public/images/../../"

        attack_url = augment_url(base_path, payload)
        rows.append({"payload": attack_url, "is_attack": 1})

    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"Saved {len(df)} records to {OUTPUT_FILE}")

if __name__ == "__main__":
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
    generate_juice_data()
