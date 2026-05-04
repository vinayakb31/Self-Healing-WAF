#!/bin/bash
set -euo pipefail

echo "==============================="
echo "WAF Latency Benchmark"
echo "==============================="

echo ""
echo "Test 1 - Baseline (no WAF, direct to backend port 8080):"
ab -n 1000 -c 10 http://127.0.0.1:8080/ 2>/dev/null | grep -E "Time per request|Requests per second|Failed"

echo ""
echo "Test 2 - With WAF (through nginx port 80):"
ab -n 1000 -c 10 http://127.0.0.1:80/ 2>/dev/null | grep -E "Time per request|Requests per second|Failed"

echo ""
echo "Test 3 - Concurrent load (100 concurrent users):"
ab -n 5000 -c 100 http://127.0.0.1:80/ 2>/dev/null | grep -E "Time per request|Requests per second|Failed|Percentage"

echo ""
echo "WAF overhead per request (check /tmp/waf_intercept.log):"
tail -20 /tmp/waf_intercept.log \
  | grep -oP '[0-9]+\.[0-9]+ms' \
  | awk -F'ms' '{sum+=$1; count++} END {
      if (count > 0) {
          printf "Average WAF processing time: %.3fms over %d requests\n", sum/count, count
      } else {
          print "Average WAF processing time: no samples found"
      }
  }'
