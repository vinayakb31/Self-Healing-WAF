#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAF_DIR="$SCRIPT_DIR"
PROJECT_HOME="$(dirname "$WAF_DIR")"
BACKEND_DIR="${BACKEND_DIR:-$PROJECT_HOME/backend}"
PYTHON_BIN="$WAF_DIR/.venv/bin/python"
RUN_AS_USER="${SUDO_USER:-}"

echo "Starting live WAF stack..."
echo "WAF directory: $WAF_DIR"

pkill -f 'waf_inference.py' 2>/dev/null || true
pkill -f 'self_heal_loop.py' 2>/dev/null || true
sudo killall nginx 2>/dev/null || true

if ! ss -ltn 2>/dev/null | grep -q ':8080 '; then
    if [ ! -d "$BACKEND_DIR" ]; then
        echo "Backend directory not found: $BACKEND_DIR"
        exit 1
    fi
    echo "Starting backend on port 8080..."
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

sudo rm -f /tmp/waf_intercept.log /tmp/waf_inference.out
sudo touch /tmp/waf_intercept.log /tmp/waf_inference.out
sudo chmod 777 /tmp/waf_intercept.log /tmp/waf_inference.out

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

# Warm the inference path, then clear the demo log.
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

echo ""
echo "Nginx processes:"
ps -C nginx -o pid,user,args
echo ""
echo "AI worker:"
pgrep -af waf_inference.py || true
echo ""
echo "Self-healing worker:"
pgrep -af self_heal_loop.py || true
echo ""
echo "Live WAF stack ready."
