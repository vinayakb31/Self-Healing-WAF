#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_DIR="$SCRIPT_DIR"
PROJECT_HOME="$(dirname "$WAF_DIR")"
BACKEND_DIR="${BACKEND_DIR:-$PROJECT_HOME/backend}"
PYTHON_BIN="$WAF_DIR/.venv/bin/python"
RUN_AS_USER="${SUDO_USER:-}"

echo "==============================="
echo "WAF Stress Test - 1000 requests"
echo "==============================="
echo "WAF directory: $WAF_DIR"

# Clean up
pkill -f 'waf_inference.py' 2>/dev/null || true
pkill -f 'self_heal_loop.py' 2>/dev/null || true
sudo rm -f /tmp/waf_intercept.log /tmp/waf_inference.out
sudo touch /tmp/waf_intercept.log /tmp/waf_inference.out
sudo chmod 777 /tmp/waf_intercept.log /tmp/waf_inference.out

if ! ss -ltn 2>/dev/null | grep -q ':8080 '; then
    if [ ! -d "$BACKEND_DIR" ]; then
        echo "Backend directory not found: $BACKEND_DIR"
        exit 1
    fi
    if [ "$(id -u)" -eq 0 ] && [ -n "$RUN_AS_USER" ] && [ "$RUN_AS_USER" != "root" ]; then
        (cd "$BACKEND_DIR" && sudo -u "$RUN_AS_USER" setsid python3 -m http.server 8080 > /tmp/waf_backend.out 2>&1 < /dev/null &)
    else
        (cd "$BACKEND_DIR" && setsid python3 -m http.server 8080 > /tmp/waf_backend.out 2>&1 < /dev/null &)
    fi
    sleep 1
fi

ipcrm -M 0x1234 2>/dev/null || true
ipcrm -S 0x5678 2>/dev/null || true
ipcrm -Q 0x9ABC 2>/dev/null || true
sudo killall nginx 2>/dev/null || true
sudo /etc/nginx/sbin/nginx

if [ ! -x "$PYTHON_BIN" ]; then
    echo "Python venv not found: $PYTHON_BIN"
    exit 1
fi

cd "$WAF_DIR"
if [ "$(id -u)" -eq 0 ] && [ -n "$RUN_AS_USER" ] && [ "$RUN_AS_USER" != "root" ]; then
    (sudo -u "$RUN_AS_USER" setsid "$PYTHON_BIN" -u waf_inference.py > /tmp/waf_inference.out 2>&1 < /dev/null &)
else
    (setsid "$PYTHON_BIN" -u waf_inference.py > /tmp/waf_inference.out 2>&1 < /dev/null &)
fi

ready=0
for _ in $(seq 1 40); do
    if grep -q "Waiting for requests" /tmp/waf_inference.out 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.25
done

if [ "$ready" -ne 1 ]; then
    echo "AI worker did not become ready. Last worker output:"
    tail -40 /tmp/waf_inference.out || true
    exit 1
fi

curl -s http://localhost/ > /dev/null || true
sudo truncate -s 0 /tmp/waf_intercept.log

if [ -f "$WAF_DIR/self_heal_loop.py" ]; then
    sudo rm -f /tmp/waf_self_heal.out
    sudo touch /tmp/waf_self_heal.out
    sudo chmod 777 /tmp/waf_self_heal.out
    if [ "$(id -u)" -eq 0 ] && [ -n "$RUN_AS_USER" ] && [ "$RUN_AS_USER" != "root" ]; then
        (cd "$WAF_DIR" && sudo -u "$RUN_AS_USER" setsid "$PYTHON_BIN" -u self_heal_loop.py > /tmp/waf_self_heal.out 2>&1 < /dev/null &)
    else
        (cd "$WAF_DIR" && setsid "$PYTHON_BIN" -u self_heal_loop.py > /tmp/waf_self_heal.out 2>&1 < /dev/null &)
    fi
fi

normal_status="/tmp/waf_normal_status.$$"
attack_status="/tmp/waf_attack_status.$$"
rm -f "$normal_status" "$attack_status"

echo ""
echo "Sending 1000 mixed requests (normal + attacks)..."

# Send normal requests
for i in $(seq 1 400); do
    curl -s -o /dev/null -w "%{http_code}\n" http://localhost >> "$normal_status" &
done

# Send attack requests
for i in $(seq 1 300); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -d "username=admin' OR '1'='1&password=x" >> "$attack_status" &
done

# Send more attacks
for i in $(seq 1 300); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost \
         -H "Content-Type: application/x-www-form-urlencoded" \
         -d "'; DROP TABLE users; --" >> "$attack_status" &
done

# Wait for all requests to finish
wait

echo "All 1000 requests sent!"
echo ""
echo "Results:"
echo "Total intercepted: $(wc -l < /tmp/waf_intercept.log)"
echo "Nginx worker processes: $(ps -C nginx -o args= | grep -c 'nginx: worker process')"
echo "Normal 200 responses: $(grep -c '^200$' "$normal_status" 2>/dev/null || true) / 400"
echo "Attack 403 responses: $(grep -c '^403$' "$attack_status" 2>/dev/null || true) / 600"
echo ""
echo "Sample of captured payloads:"
tail -5 /tmp/waf_intercept.log

rm -f "$normal_status" "$attack_status"
