import requests, json

print("=== Testing /health ===")
r = requests.get("http://127.0.0.1:8000/health")
print(json.dumps(r.json(), indent=2))

print("\n=== Testing /predict (attack payload) ===")
attack = "http://localhost:8080/app/login?user=admin' OR 1=1--&pwd=x HTTP/1.1"
r = requests.post("http://127.0.0.1:8000/predict", json={"request_string": attack})
print(json.dumps(r.json(), indent=2))

print("\n=== Testing /predict (normal payload) ===")
normal = "http://localhost:8080/tienda1/imagenes/nuevo_logo.png"
r = requests.post("http://127.0.0.1:8000/predict", json={"request_string": normal})
print(json.dumps(r.json(), indent=2))

print("\n=== Testing /shadow (XSS payload) ===")
xss = "http://localhost:8080/app?q=<script>alert('XSS')</script> HTTP/1.1"
r = requests.post("http://127.0.0.1:8000/shadow", json={"request_string": xss})
print(json.dumps(r.json(), indent=2))

print("\n=== Testing /shadow/stats ===")
r = requests.get("http://127.0.0.1:8000/shadow/stats")
print(json.dumps(r.json(), indent=2))
