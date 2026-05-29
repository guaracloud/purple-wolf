#!/usr/bin/env bash
# Round-2 WAF benchmark orchestrator.
#
# What this runs:
#   A. Baseline (no-WAF) load: same RPS levels as round 1, against the
#      bench-baseline pod. Lets us isolate the WAF cost from Traefik's
#      floor.
#   B. purple-wolf ramp: 2000 / 4000 / 8000 / 12000 / 16000 RPS to find
#      the break point.
#   C. Broader CRS efficacy: 4536 vectors across 12 attack classes,
#      against both bench-pw and bench-coraza.
#   D. 10-minute soak at 1000 RPS with per-10s CPU+RSS sampling.
#   E. Robustness probes (header-borne, path traversal, RCE, etc.).
#
# Assumes already-applied: benchmarks/k8s/waf-bench.yaml +
# benchmarks/k8s/baseline.yaml + the imagePullSecret (`ghcr-pull`)
# documented in docs/homelab-test.md.

set -euo pipefail

NS="${BENCH_NAMESPACE:-waf-bench}"
TS="$(date -u +%Y%m%d-%H%M%S)"
OUT_LOCAL="benchmarks/results/round2-${TS}"
mkdir -p "$OUT_LOCAL"
echo "[orch] results dir: $OUT_LOCAL"

RUNNER_DIR="benchmarks/runner/round2"

# ────────────────────────────── 1. Build the corpus locally ──
echo "[orch] (re)building extended corpus…"
python3 "$RUNNER_DIR/build-extended-corpus.py" --out "$OUT_LOCAL/attacks-extended.jsonl"

# ───────────────────────────── 2. Ensure runner Pod ──
echo "[orch] (re)launching bench-runner…"
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
          apk add --quiet curl wget tar jq ca-certificates >/dev/null 2>&1 || true
          VG=12.12.0
          if [ ! -x /usr/local/bin/vegeta ]; then
            wget -qO /tmp/vg.tgz "https://github.com/tsenart/vegeta/releases/download/v${VG}/vegeta_${VG}_linux_amd64.tar.gz"
            tar -xzf /tmp/vg.tgz -C /usr/local/bin vegeta
            chmod +x /usr/local/bin/vegeta
          fi
          pip install --quiet httpx==0.27.0 >/dev/null 2>&1 || true
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
kubectl -n "$NS" wait --for=condition=Ready pod/bench-runner --timeout=180s >/dev/null
until kubectl -n "$NS" exec bench-runner -- sh -c 'command -v vegeta && command -v jq && python3 -c "import httpx"' >/dev/null 2>&1; do
  echo -n "."; sleep 2
done
echo
echo "[orch] runner ready"

# Push the corpus + the round-2 efficacy script into the runner.
kubectl -n "$NS" cp "$OUT_LOCAL/attacks-extended.jsonl" \
  bench-runner:/tmp/attacks-extended.jsonl
kubectl -n "$NS" cp "$RUNNER_DIR/runeff.sh" bench-runner:/tmp/runeff.sh
kubectl -n "$NS" exec bench-runner -- chmod +x /tmp/runeff.sh

# ───────────────────────────── 3. Baseline (no-WAF) load ──
echo
echo "==================== baseline (no-WAF) =========================="
kubectl -n "$NS" exec bench-runner -- sh -c "
  rm -f /out/baseline-load.jsonl
  cp /corpus/load-targets.txt /tmp/targets-baseline.txt
  sed -i 's#__TARGET__#http://bench-baseline:8080#g' /tmp/targets-baseline.txt
  python3 /scripts/load.py \
    --target http://bench-baseline:8080 --label baseline \
    --targets-file /tmp/targets-baseline.txt --rps 100,500,1000 \
    --duration 30s --iters 2 --out /out/baseline-load.jsonl
"
kubectl -n "$NS" exec bench-runner -- cat /out/baseline-load.jsonl \
  > "$OUT_LOCAL/baseline-load.jsonl"

# ───────────────────────────── 4. purple-wolf ramp ──
echo
echo "==================== purple-wolf ramp =========================="
kubectl -n "$NS" rollout restart deploy/bench-pw >/dev/null
kubectl -n "$NS" rollout status  deploy/bench-pw --timeout=120s >/dev/null
kubectl -n "$NS" exec bench-runner -- sh -c "
  rm -f /out/pw-ramp-load.jsonl /out/pw-ramp2-load.jsonl
  cp /corpus/load-targets.txt /tmp/targets-pw.txt
  sed -i 's#__TARGET__#http://bench-pw:8080#g' /tmp/targets-pw.txt
  python3 /scripts/load.py --target http://bench-pw:8080 --label pw-ramp \
    --targets-file /tmp/targets-pw.txt --rps 2000,4000,8000 \
    --duration 30s --iters 2 --out /out/pw-ramp-load.jsonl
  python3 /scripts/load.py --target http://bench-pw:8080 --label pw-ramp2 \
    --targets-file /tmp/targets-pw.txt --rps 12000,16000 \
    --duration 30s --iters 2 --out /out/pw-ramp2-load.jsonl
"
kubectl -n "$NS" exec bench-runner -- cat /out/pw-ramp-load.jsonl  > "$OUT_LOCAL/pw-ramp-load.jsonl"
kubectl -n "$NS" exec bench-runner -- cat /out/pw-ramp2-load.jsonl > "$OUT_LOCAL/pw-ramp2-load.jsonl"

# ───────────────────────────── 5. Extended efficacy ──
echo
echo "==================== extended efficacy =========================="
for WAF in pw coraza; do
  echo "[orch] $WAF: restart pod, then run extended corpus…"
  kubectl -n "$NS" rollout restart deploy/bench-$WAF >/dev/null
  kubectl -n "$NS" rollout status  deploy/bench-$WAF --timeout=180s >/dev/null

  kubectl -n "$NS" exec bench-runner -- sh -c "
    nohup sh /tmp/runeff.sh http://bench-$WAF:8080 $WAF-ext \
      /tmp/attacks-extended.jsonl /out/$WAF-ext.csv > /out/$WAF-ext.log 2>&1 &
    echo \$! > /out/$WAF-ext.pid
  "
  # Poll until the runeff process exits.
  while kubectl -n "$NS" exec bench-runner -- \
      sh -c "kill -0 \$(cat /out/$WAF-ext.pid 2>/dev/null) 2>/dev/null" 2>/dev/null; do
    n=$(kubectl -n "$NS" exec bench-runner -- wc -l "/out/$WAF-ext.csv" 2>/dev/null | awk '{print $1}')
    echo "  $WAF: $n / $(wc -l < "$OUT_LOCAL/attacks-extended.jsonl")"
    sleep 30
  done
  kubectl -n "$NS" exec bench-runner -- cat /out/$WAF-ext.csv > "$OUT_LOCAL/$WAF-ext.csv"
done

# ───────────────────────────── 6. 10-min soak ──
echo
echo "==================== 10-min soak (1000 RPS) =========================="
kubectl -n "$NS" rollout restart deploy/bench-pw >/dev/null
kubectl -n "$NS" rollout status  deploy/bench-pw --timeout=120s >/dev/null
kubectl -n "$NS" exec bench-runner -- sh -c "
  cp /corpus/load-targets.txt /tmp/targets-soak.txt
  sed -i 's#__TARGET__#http://bench-pw:8080#g' /tmp/targets-soak.txt
  nohup python3 /scripts/load.py \
    --target http://bench-pw:8080 --label pw-soak \
    --targets-file /tmp/targets-soak.txt --rps 1000 \
    --duration 10m --iters 1 --warmup-seconds 5 \
    --out /out/pw-soak-load.jsonl > /out/soak.log 2>&1 &
  echo \$! > /out/soak.pid
"
# Resource sampler runs in parallel for the soak duration.
RES_OUT="$OUT_LOCAL/pw-soak-resources.csv"
: >"$RES_OUT"
end=$(($(date +%s) + 660))
while [ "$(date +%s)" -lt "$end" ]; do
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kubectl -n "$NS" top pod -l 'waf=purple-wolf' --no-headers --containers 2>/dev/null \
    | awk -v ts="$ts" '{print ts","$2","$3","$4}' >>"$RES_OUT" || true
  sleep 10
done
kubectl -n "$NS" exec bench-runner -- cat /out/pw-soak-load.jsonl \
  > "$OUT_LOCAL/pw-soak-load.jsonl"

# ───────────────────────────── 7. Robustness probes ──
echo
echo "==================== robustness probes =========================="
bash "$RUNNER_DIR/robustness.sh" > "$OUT_LOCAL/robustness.txt"

echo
echo "[orch] done. Results in $OUT_LOCAL/"
ls -la "$OUT_LOCAL"
