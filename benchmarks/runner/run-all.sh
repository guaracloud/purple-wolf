#!/usr/bin/env bash
# WAF benchmark orchestrator.
#
# Brings up the runner Pod, ships the corpora + scripts via
# ConfigMaps, executes efficacy + load tests against each of the two
# WAF Services side-by-side, samples resource usage during the load
# tests, and saves everything under benchmarks/results/<timestamp>/.
#
# Re-runnable end-to-end. Assumes:
#   - benchmarks/k8s/waf-bench.yaml is already applied and both
#     bench-pw + bench-coraza Pods are 2/2 Running.
#   - kubectl context is set to the homelab cluster.
#   - The current working directory is the repo root.

set -euo pipefail

ts="$(date -u +%Y%m%d-%H%M%S)"
NS="${BENCH_NAMESPACE:-waf-bench}"
OUT_LOCAL="benchmarks/results/${ts}"
mkdir -p "$OUT_LOCAL"
echo "[orch] results dir: $OUT_LOCAL"

RPS="${BENCH_RPS:-100,500,1000}"
DURATION="${BENCH_DURATION:-30s}"
ITERS="${BENCH_ITERS:-2}"
EFF_CONCURRENCY="${BENCH_EFFICACY_CONCURRENCY:-8}"

# ───────────────────────────── corpus + scripts → ConfigMaps ──
echo "[orch] re-creating ConfigMaps from local files…"
kubectl -n "$NS" delete cm bench-corpora bench-runner-scripts --ignore-not-found 2>/dev/null || true
kubectl -n "$NS" create cm bench-corpora \
  --from-file=benchmarks/corpora/attacks.jsonl \
  --from-file=benchmarks/corpora/benign.jsonl \
  --from-file=benchmarks/corpora/load-targets.txt >/dev/null
kubectl -n "$NS" create cm bench-runner-scripts \
  --from-file=benchmarks/runner/efficacy.py \
  --from-file=benchmarks/runner/load.py >/dev/null

# ───────────────────────────────────────────── runner Pod ──
echo "[orch] (re)launching runner Pod…"
kubectl -n "$NS" delete pod bench-runner --ignore-not-found --wait=true >/dev/null 2>&1 || true
cat <<'EOF' | kubectl -n "$NS" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: { name: bench-runner, labels: { app.kubernetes.io/name: bench-runner } }
spec:
  restartPolicy: Never
  nodeSelector: { kubernetes.io/hostname: homelab-01 }
  containers:
    - name: runner
      image: docker.io/python:3.12-alpine
      command: ["sh", "-c"]
      args:
        - |
          set -eu
          apk add --quiet curl wget tar ca-certificates >/dev/null 2>&1 || true
          VG_VERSION=12.12.0
          if [ ! -x /usr/local/bin/vegeta ]; then
            wget -qO /tmp/vg.tgz "https://github.com/tsenart/vegeta/releases/download/v${VG_VERSION}/vegeta_${VG_VERSION}_linux_amd64.tar.gz"
            tar -xzf /tmp/vg.tgz -C /usr/local/bin vegeta
            chmod +x /usr/local/bin/vegeta
          fi
          pip install --quiet httpx==0.27.0 >/dev/null 2>&1 || pip install httpx==0.27.0
          mkdir -p /out
          sleep 36000
      volumeMounts:
        - { name: corpora, mountPath: /corpus, readOnly: true }
        - { name: scripts, mountPath: /scripts, readOnly: true }
        - { name: results, mountPath: /out }
      resources:
        requests: { cpu: 200m, memory: 256Mi }
        limits: { memory: 1Gi }
  volumes:
    - { name: corpora, configMap: { name: bench-corpora } }
    - { name: scripts, configMap: { name: bench-runner-scripts } }
    - { name: results, emptyDir: {} }
EOF

echo "[orch] waiting for runner ready…"
kubectl -n "$NS" wait --for=condition=Ready pod/bench-runner --timeout=180s >/dev/null

# Wait for the in-pod init (wget vegeta + pip install) to finish.
echo -n "[orch] waiting for vegeta + httpx in pod"
for _ in $(seq 1 30); do
  if kubectl -n "$NS" exec bench-runner -- sh -c 'command -v vegeta && python3 -c "import httpx"' >/dev/null 2>&1; then
    echo " ✓"; break
  fi
  echo -n "."; sleep 2
done

# ───────────────────────────────────────────── helpers ──
sample_resources() {
  # $1=label  $2=duration_secs  $3=outfile
  local label="$1" dur="$2" out="$3"
  : >"$out"
  local end=$(($(date +%s) + dur))
  while [ "$(date +%s)" -lt "$end" ]; do
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    kubectl -n "$NS" top pod -l "waf=$label" --no-headers --containers 2>/dev/null \
      | awk -v ts="$ts" -v lbl="$label" '{print ts","lbl","$2","$3","$4}' >>"$out" || true
    sleep 1
  done
}

run_for_waf() {
  local label="$1"   # purple-wolf or coraza
  local target="$2"  # http://bench-pw:8080
  echo
  echo "==================== $label =========================="
  echo "[orch] efficacy run for $label …"
  kubectl -n "$NS" exec bench-runner -- sh -c "
    rm -f /out/${label}-efficacy-summary.jsonl /out/${label}-efficacy-raw.jsonl
    python3 /scripts/efficacy.py \
      --target $target \
      --label $label \
      --attacks /corpus/attacks.jsonl \
      --benign  /corpus/benign.jsonl \
      --concurrency ${EFF_CONCURRENCY} \
      --out-summary /out/${label}-efficacy-summary.jsonl \
      --out-raw     /out/${label}-efficacy-raw.jsonl
  "
  echo "[orch] copying efficacy results to host…"
  kubectl -n "$NS" exec bench-runner -- cat "/out/${label}-efficacy-summary.jsonl" \
    > "$OUT_LOCAL/${label}-efficacy-summary.jsonl"
  kubectl -n "$NS" exec bench-runner -- cat "/out/${label}-efficacy-raw.jsonl" \
    > "$OUT_LOCAL/${label}-efficacy-raw.jsonl"

  # ── load test: vegeta inside the runner, kubectl top in parallel
  echo "[orch] load run for $label …"
  kubectl -n "$NS" exec bench-runner -- sh -c "
    rm -f /out/${label}-load.jsonl
    # Reset placeholder hostnames in the targets file before each
    # WAF run (load.py rewrites; we want a clean slate).
    cp /corpus/load-targets.txt /tmp/targets.txt
    sed -i 's#__TARGET__#$target#g' /tmp/targets.txt
    python3 /scripts/load.py \
      --target $target \
      --label $label \
      --targets-file /tmp/targets.txt \
      --rps ${RPS} \
      --duration ${DURATION} \
      --iters ${ITERS} \
      --out /out/${label}-load.jsonl
  " &
  bench_pid=$!

  # Estimate total seconds for the resource sampler.
  rps_count=$(echo "$RPS" | tr ',' ' ' | wc -w | tr -d ' ')
  per_run="${DURATION%s}"
  total_sec=$((rps_count * ITERS * per_run + 30))
  sample_resources "$label" "$total_sec" "$OUT_LOCAL/${label}-resources.csv" &
  sampler_pid=$!

  wait $bench_pid
  kill $sampler_pid 2>/dev/null || true
  wait $sampler_pid 2>/dev/null || true
  kubectl -n "$NS" exec bench-runner -- cat "/out/${label}-load.jsonl" \
    > "$OUT_LOCAL/${label}-load.jsonl"
}

# ───────────────────────────────────────────── runs ──
run_for_waf purple-wolf http://bench-pw:8080
run_for_waf coraza       http://bench-coraza:8080

# Copy raw per-request results too.
echo
echo "[orch] done. Results in $OUT_LOCAL/"
ls -la "$OUT_LOCAL"
