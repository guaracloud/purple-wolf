#!/bin/sh
# Single-stream efficacy runner, one request per line, streaming
# output. Designed to run inside the bench-runner Pod.
#
# Why bash+jq+curl instead of the round-1 Python streaming runner:
# the Python version's file write buffer hid progress at the
# volumes round 2 drove (4536 records × 2 WAFs), making mid-run
# diagnosis hard. This loop flushes each `id|class|status` line as
# soon as curl returns.
#
# Args:
#   $1  target URL (e.g. http://bench-pw:8080)
#   $2  label written nowhere — just kept for symmetry with round 1
#   $3  corpus JSONL path (one record per line)
#   $4  output CSV path; lines are `id|class|status`
#
# Requires inside the runner Pod:
#   apk add --quiet jq curl
#
# Run from the orchestrator on a host with kubectl access:
#   kubectl -n waf-bench cp benchmarks/runner/round2/runeff.sh \
#       bench-runner:/tmp/runeff.sh
#   kubectl -n waf-bench exec bench-runner -- sh /tmp/runeff.sh \
#       http://bench-pw:8080 pw /tmp/attacks-extended.jsonl /out/pw.csv

set -eu
TARGET="$1"
LABEL="$2"
CORPUS="$3"
OUT="$4"

: >"$OUT"
n=0

while IFS= read -r line; do
  n=$((n + 1))
  id=$(echo "$line" | jq -r '.id')
  cls=$(echo "$line" | jq -r '.class')
  method=$(echo "$line" | jq -r '.method')
  path=$(echo "$line" | jq -r '.path')
  query=$(echo "$line" | jq -r '.query')
  body=$(echo "$line" | jq -r '.body')
  ct=$(echo "$line" | jq -r '.headers["Content-Type"] // .headers["content-type"] // empty')
  ua=$(echo "$line" | jq -r '.headers["User-Agent"] // .headers["user-agent"] // empty')

  url="$TARGET$path"
  [ -n "$query" ] && url="$url?$query"

  if [ -n "$body" ]; then
    status=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X "$method" \
      ${ct:+-H "Content-Type: $ct"} \
      ${ua:+-H "User-Agent: $ua"} \
      --data-binary "$body" "$url" 2>/dev/null || echo 0)
  else
    status=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X "$method" \
      ${ua:+-H "User-Agent: $ua"} \
      "$url" 2>/dev/null || echo 0)
  fi

  echo "$id|$cls|$status" >>"$OUT"
  if [ $((n % 200)) -eq 0 ]; then
    echo "  [$LABEL] $n …" >&2
  fi
done <"$CORPUS"

echo "[$LABEL] done, $n records" >&2
