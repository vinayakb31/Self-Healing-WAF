import sqlite3
from datetime import datetime

print("Forging mock waf_quarantine.db for retraining tests...")

# 1. Create the database connection
conn = sqlite3.connect("waf_quarantine.db")
cursor = conn.cursor()

# 2. Build the exact schema the C++ interceptor will use
cursor.execute('''
    CREATE TABLE IF NOT EXISTS blocked_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
        request_payload TEXT,
        ai_confidence_score REAL,
        status TEXT
    )
''')

# 3. Inject mock data representing human-reviewed logs
mock_logs = [
    # Case 1: A False Positive we want to teach the AI to allow
    (datetime.now().isoformat(), "192.168.1.50", "http://localhost:8080/tienda1/imagenes/nuevo_logo.png", 0.88, "VERIFIED_NORMAL"),
    (datetime.now().isoformat(), "192.168.1.51", "http://localhost:8080/tienda1/publico/carrito.jsp?checkout=true", 0.75, "VERIFIED_NORMAL"),
    
    # Case 2: A new type of attack we want to teach the AI to block
    (datetime.now().isoformat(), "10.0.45.2", "http://localhost:8080/tienda1/publico/entrar.jsp?user=<img src=x onerror=alert(1)>", 0.45, "VERIFIED_ATTACK"),
    (datetime.now().isoformat(), "10.0.45.3", "http://localhost:8080/tienda1/config.bak HTTP/1.1", 0.55, "VERIFIED_ATTACK")
]

cursor.executemany('''
    INSERT INTO blocked_requests (timestamp, ip_address, request_payload, ai_confidence_score, status)
    VALUES (?, ?, ?, ?, ?)
''', mock_logs)

conn.commit()
conn.close()

print("Success. The mock database is ready.")