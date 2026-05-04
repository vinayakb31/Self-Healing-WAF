#!/bin/bash
set -euo pipefail

RULES_FILE="$HOME/waf_shm/generated_rules.txt"
TOKEN="selfheal-demo-attack-$(date +%s)"

before=$(curl -s -o /tmp/selfheal_before.out -w "%{http_code}" "http://localhost/$TOKEN")

printf "\nSelfHealDemo | %s\n" "$TOKEN" >> "$RULES_FILE"
sleep 4

after=$(curl -s -o /tmp/selfheal_after.out -w "%{http_code}" "http://localhost/$TOKEN")

echo "Token: $TOKEN"
echo "Before generated rule: $before"
echo "After generated rule:  $after"
echo ""
echo "Worker log:"
tail -14 /tmp/waf_inference.out
echo ""
echo "WAF log:"
tail -8 /tmp/waf_intercept.log
