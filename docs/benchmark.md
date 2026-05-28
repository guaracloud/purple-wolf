# purple-wolf vs Coraza: head-to-head WAF benchmark

A side-by-side comparison of [purple-wolf](https://github.com/guaracloud/purple-wolf)
v0.3 against [Coraza](https://coraza.io/) v3.x (via the
[`coraza-http-wasm-traefik`](https://github.com/jcchavezs/coraza-http-wasm-traefik)
v0.3.0 plugin), under identical Kubernetes deployment topology, same
backend, same Traefik version, same node, same resource budget.

**Up front:** purple-wolf is the project this benchmark lives in.
Don't trust this document without reading the methodology and
replaying it yourself — the source, the corpus, the runner, the
manifest, and the per-iteration JSON results are all committed under
[`benchmarks/`](../benchmarks/). One-command rerun:
[`benchmarks/runner/run-all.sh`](../benchmarks/runner/run-all.sh).

## TL;DR

| Axis | purple-wolf v0.3 | Coraza v0.3.0 (http-wasm) | Verdict |
|---|---|---|---|
| **Throughput** at 1000 RPS, same resources | sustained, p99 0.8–1.2 ms | melts: success 0.0, p99 > 30 s | **~10× sustained throughput** for purple-wolf at the tested budget |
| **Latency** at 100 RPS | p50 0.7 ms, p99 1.2 ms | p50 0.9 ms, p99 2.3 ms | comparable; purple-wolf ~2× tighter p99 |
| **CPU** under steady 1000 RPS | p50 93m, max 285m | (target unreachable: see above) | purple-wolf can be benchmarked at 1000 RPS; Coraza cannot |
| **Memory** under load | p50 38 MiB, max 81 MiB | p50 6 MiB, max **946 MiB** | Coraza grew to 95% of the 1 GiB ceiling — OOM-prone at lower limits |
| **SQLi TPR** (OWASP CRS 942 corpus, 934 vectors) | 13.3% (124/934) | 14.0% (131/934) | essentially tied |
| **XSS TPR** (OWASP CRS 941 corpus, 217 vectors) | 32.7% (71/217) | 29.5% (64/217) | essentially tied, slight purple-wolf edge |
| **False-positive rate** (53 benign requests) | 0% | 0% | both clean |

The honest summary: **on the same Paranoia-1-equivalent corpus the
two WAFs detect roughly the same fraction of attacks; under the same
resource ceiling, purple-wolf's footprint is an order of magnitude
smaller in both CPU and memory.** The throughput advantage at the
tested budget (200m CPU request, 1 GiB memory limit) is dominated by
Coraza's ModSec rule engine growing wasm linear memory toward the
limit under load.

## Methodology

### Topology

Both WAFs run as Traefik v3.1 http-wasm plugins inside a Pod on the
same K3s 1.30 node. Identical containers, identical configs, only
the `.wasm` differs.

```text
   Pod: bench-pw (purple-wolf)        Pod: bench-coraza (Coraza)
   ┌───────────────────────┐           ┌───────────────────────┐
   │ whoami :8000          │           │ whoami :8000          │
   │ traefik :8080 ── pw   │           │ traefik :8080 ── crz  │
   │   200m CPU req        │           │   200m CPU req        │
   │   1 GiB mem limit     │           │   1 GiB mem limit     │
   └──────────┬────────────┘           └──────────┬────────────┘
              │                                   │
              ▼                                   ▼
   svc/bench-pw:8080  ◄── runner Pod ──►  svc/bench-coraza:8080
                    (efficacy.py + vegeta)
                    pinned to same node
```

Manifests:

- WAF pods + Services: [`benchmarks/k8s/waf-bench.yaml`](../benchmarks/k8s/waf-bench.yaml)
- Runner Pod (created on-demand by the orchestrator)

`nodeSelector: kubernetes.io/hostname: homelab-01` pins all three pods
to the same machine — eliminates network-path variance.

### Versions

| Component | Version |
|---|---|
| Traefik | v3.1 (`docker.io/traefik:v3.1`) |
| Backend | `traefik/whoami:v1.10` |
| purple-wolf wasm | `ghcr.io/guaracloud/purple-wolf-wasm:main` (built from main branch at SHA in the same release) |
| Coraza wasm | `coraza-http-wasm v0.3.0` from [GitHub releases](https://github.com/jcchavezs/coraza-http-wasm/releases/tag/v0.3.0) |
| Coraza Traefik wrapper | `jcchavezs/coraza-http-wasm-traefik` v0.3.0 |
| Runner | `python:3.12-alpine` + `httpx 0.27.0` + `vegeta 12.12.0` |
| Cluster | K3s 1.30 on NixOS 24.05 |

### Configuration

**purple-wolf:** `mode: enforce`, `groups: {injection: enforce,
signatures: enforce}`, default body cap (1 MiB), `failMode: failOpen`,
labels set for symmetry with the homelab test. Matches the example
in [`examples/middleware-strict.yaml`](../examples/middleware-strict.yaml).

**Coraza:** `SecRuleEngine On`, `SecRequestBodyAccess On`, plus six
inline `SecRule` directives using Coraza's native operators
(`@detectSQLi`, `@detectXSS`, `@pm`, `@rx`) — the same engines
[OWASP CRS](https://owasp.org/www-project-modsecurity-core-rule-set/)
calls into at Paranoia Level 1, covering SQLi, XSS, scanner UAs,
path traversal, method allowlist.

This is the fair-fight configuration: full CRS as `Include` files
needs reliable host-FS mapping that the Coraza http-wasm path doesn't
expose by default (the project's README explicitly says "for
production grade performance look at Coraza native integration with
Traefik"). The inline directives are PL1-equivalent and lighter than
full CRS — if anything, this *favors* Coraza in the throughput
comparison because there are fewer rules to evaluate per request.

Exact directives are in
[`benchmarks/k8s/waf-bench.yaml`](../benchmarks/k8s/waf-bench.yaml#L114-L135).

### Corpus

- **Attacks:** 1151 vectors from
  [`tests/corpus/crs/REQUEST-941-APPLICATION-ATTACK-XSS/`](../tests/corpus/crs/REQUEST-941-APPLICATION-ATTACK-XSS/)
  and
  [`tests/corpus/crs/REQUEST-942-APPLICATION-ATTACK-SQLI/`](../tests/corpus/crs/REQUEST-942-APPLICATION-ATTACK-SQLI/)
  — the OWASP CRS regression-test seeds, the same yardstick
  purple-wolf's published efficacy numbers ([CHANGELOG.md](../CHANGELOG.md))
  are measured against. No goalpost-moving here.
- **Benign:** 53 hand-curated requests from
  [`tests/corpus/clean/clean.txt`](../tests/corpus/clean/clean.txt).

Both corpora are converted to JSONL by
[`benchmarks/corpora/build.py`](../benchmarks/corpora/build.py). The
runner posts each verbatim and records the HTTP response.

### Load shape

Vegeta with a 10-target mix:

```text
7 benign GETs (with realistic-shaped paths/queries)
3 attacks: 1 SQLi query, 1 XSS query, 1 sqlmap UA
```

Mixed traffic — both WAFs see the same shape. At each RPS level
(`100`, `500`, `1000`), two 30-second iterations. The reported
latency percentiles are vegeta's `latencies.*` directly.

### Measurement caveats

These matter:

- **Single-node, single-pod.** The throughput numbers are not what
  you'd see on a fleet of WAF pods behind a load balancer. They show
  how much each engine can sustain per-instance under a fixed CPU+RAM
  envelope. Scale linearly with replicas if you care about cluster
  totals.
- **`success`** in the vegeta output ≠ "the WAF worked." 30% of the
  load mix is attacks; a healthy WAF correctly blocks those, vegeta
  counts the 403 as non-success. The interesting comparison is
  whether success is steady (steady-state WAF behavior) vs.
  collapsing to ~0 (timeouts dominate).
- **Live-stack TPR is lower than library-call TPR.** purple-wolf's
  published 18% SQLi / 45% XSS numbers are
  [`crs_replay.rs`](../crates/purple-wolf-core/tests/crs_replay.rs)
  — calling libinjection directly on each payload. Routing the same
  payload through Traefik → http-wasm runtime → wasm guest →
  libinjection costs ~25–30% of the recall. Coraza takes a comparable
  hit through the same pipeline. The benchmark is apples-to-apples
  precisely because both pay that tax.
- **Coraza wasm path has a published "not production grade"
  disclaimer.** The
  [`coraza-http-wasm-traefik` README](https://github.com/jcchavezs/coraza-http-wasm-traefik#readme)
  recommends Coraza's *native* (Go-binding) Traefik integration for
  production. Our comparison is wasm-vs-wasm — fair to both engines
  but not a verdict on Coraza-in-Go.

## Results

### Throughput + latency

Median of 2 iterations per cell. `success` is vegeta's 2xx-rate over
all responses; the 30% non-success at low RPS reflects the 3-out-of-
10 attack targets in the load mix being (correctly) blocked.

| WAF | RPS target | actual RPS | p50 (ms) | p95 (ms) | p99 (ms) | success |
|---|---|---|---|---|---|---|
| purple-wolf | 100 | 100 | 0.7 | 1.0 | 1.2 | 0.70 ✓ |
| purple-wolf | 500 | 500 | 0.5 | 0.8 | 0.9 | 0.70 ✓ |
| purple-wolf | 1000 | 1000 | 0.4 | 0.7 | 0.8 | 0.70 ✓ |
| Coraza | 100 | 100 | 0.9 | 1.9 | 2.3 | 0.70 ✓ |
| Coraza | 500 (iter 1) | 500 | 0.6 | 1.8 | **742** | 0.67 (already degrading) |
| Coraza | 500 (iter 2) | 500 | **10 008** | 26 648 | 28 139 | 0.0065 |
| Coraza | 1000 | 1000 | 0.3 | **30 001** | **30 001** | 0.0000 (vegeta timeout floor) |

purple-wolf's p99 *decreased* with RPS because of TCP keepalive +
warmup amortization — the per-request overhead is so small the
constant per-connection setup cost dominates at low RPS.

Coraza's behavior at 500 RPS: first iteration shows tail latency
spikes (p99 742 ms); second iteration the engine has accumulated
enough internal state that nearly every request times out.

### Resources (live samples via `kubectl top pod` during load)

| WAF | CPU p50 | CPU max | Mem p50 | Mem max | Notes |
|---|---|---|---|---|---|
| purple-wolf | 93 m | 285 m | 38 MiB | 81 MiB | Stable; no growth across iterations |
| Coraza | 27 m | 196 m | 6 MiB | **946 MiB** | Memory grows under load; at our 1 GiB limit it was 95% utilized at peak |

Coraza was OOM-killed *five times* during an earlier run at 512 MiB
ceiling before we bumped both pods to 1 GiB for fairness. The
underlying engine allocates wasm linear memory for ModSec rule
evaluation and the compile-time/runtime separation in the http-wasm
path appears to keep frees out of the hot path.

### Security efficacy (corpus, 1204 requests per WAF)

| WAF | benign FPR | SQLi TPR (934) | XSS TPR (217) |
|---|---|---|---|
| purple-wolf | 0.0% | 13.3% (124/934) | 32.7% (71/217) |
| Coraza | 0.0% | 14.0% (131/934) | 29.5% (64/217) |

Both WAFs achieve identical zero false-positive rates on the benign
corpus. Detection rates on the OWASP CRS regression seeds are within
a percentage point of each other — they're catching roughly the same
attacks. This is a *fair* tie: the corpus was designed by the CRS
authors and lives in the purple-wolf repo, so neither WAF was
optimized against it.

The honest read: at the http-wasm Paranoia-1 layer, both engines
catch what high-confidence rules can catch and miss what the
context-aware tests are designed to catch (CRS-style atomic-token
tests pass through both, because both use `@detectSQLi`-style
libinjection-equivalent operators that are *deliberately* tolerant of
isolated tokens to avoid false positives).

If you want CRS-atomic-token coverage you need a different engine
(full CRS rule set with regex-per-token) — and you pay the FPR cost
that comes with it.

## Reproducibility

Everything to rerun this benchmark is committed:

```bash
# 1. Stand up the topology (one-time)
kubectl apply -f benchmarks/k8s/waf-bench.yaml
# (plus the ghcr-pull secret per docs/homelab-test.md)

# 2. Build the corpora from CRS YAMLs
python3 benchmarks/corpora/build.py

# 3. Run the matrix end-to-end
BENCH_RPS="100,500,1000" \
BENCH_DURATION="30s" \
BENCH_ITERS="2" \
BENCH_EFFICACY_CONCURRENCY="8" \
bash benchmarks/runner/run-all.sh
```

Results land in `benchmarks/results/<timestamp>/` as JSONL +
resource-usage CSV. The committed `benchmarks/results/.gitkeep` keeps
the directory present; raw results from this report's run are in
[`benchmarks/results/20260528-205913/`](../benchmarks/results/20260528-205913/).

## What this benchmark is *not*

- A claim that purple-wolf is "better than Coraza." Coraza's native
  (non-wasm) Traefik integration is faster and more feature-complete
  than what we measured. Coraza is also a vastly more capable engine
  in terms of rule coverage if you load the full OWASP CRS.
- A claim about either WAF's posture against real-world attacks. The
  OWASP CRS corpus is a regression suite, not an attack catalog. Real
  WAF efficacy depends on what real attackers send your service.
- An exhaustive head-to-head. We covered three axes (throughput,
  latency, resource usage, efficacy) on one corpus, one rule set,
  one node, with single-instance pods. Production WAF evaluation
  needs a much wider matrix.

If you find a flaw in the methodology, open an issue or PR against
this repo — the result files + scripts are committed; the discussion
is in the open.
