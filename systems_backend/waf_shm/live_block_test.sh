#!/bin/bash
set -euo pipefail

echo "==============================="
echo "Live WAF Blocking Test"
echo "==============================="

normal_get=$(curl -s -o /tmp/waf_normal_get.out -w "%{http_code}" http://localhost/)
attack_get=$(curl -s -o /tmp/waf_attack_get.out -w "%{http_code}" \
  "http://localhost/search?q=%27%3B%20DROP%20TABLE%20users%3B%20--")
normal_post=$(curl -s -o /tmp/waf_normal_post.out -w "%{http_code}" \
  -X POST http://localhost/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "abc=123")
attack_post=$(curl -s -o /tmp/waf_attack_post.out -w "%{http_code}" \
  -X POST http://localhost/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin%27%20OR%20%271%27%3D%271&password=x")

echo "Normal GET status:   $normal_get"
echo "Attack GET status:   $attack_get"
echo "Normal POST status:  $normal_post"
echo "Attack POST status:  $attack_post"
echo ""
echo "Expected:"
echo "  Normal GET   -> 200"
echo "  Attack GET   -> 403"
echo "  Normal POST  -> 501 from the simple Python backend, meaning WAF allowed it"
echo "  Attack POST  -> 403"
echo ""
echo "Recent WAF decisions:"
tail -8 /tmp/waf_intercept.log
