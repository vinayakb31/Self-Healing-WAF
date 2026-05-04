import sqlite3

conn = sqlite3.connect("waf_quarantine.db")
print(conn.execute("select status, count(*) from blocked_requests group by status").fetchall())
for row in conn.execute(
    "select id, status, substr(request_payload, 1, 70), ai_confidence_score "
    "from blocked_requests order by id desc limit 8"
):
    print(row)
conn.close()
