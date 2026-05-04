import sqlite3

conn = sqlite3.connect("waf_quarantine.db")
conn.execute(
    """
    UPDATE blocked_requests
    SET status = 'VERIFIED_NORMAL'
    WHERE status = 'PENDING'
      AND (
        request_payload = 'GET http://localhost:8080/ HTTP/1.1\n'
        OR request_payload = 'POST http://localhost:8080/ HTTP/1.1\nabc=123'
      )
    """
)
conn.commit()
print(conn.execute("select status, count(*) from blocked_requests group by status").fetchall())
conn.close()
