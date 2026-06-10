# purple-wolf

A fast, low-memory Web Application Firewall delivered as a Traefik plugin.

**Status:** v0.4 released — a security & robustness hardening pass on top of
v0.3 (audit labels, webhook relay, signed release artifacts, SBOMs, Helm OCI
chart, and Kubernetes packaging). v0.4 adds an O(1) reputation limiter,
percent-decode-to-fixpoint, an expanded signature pack, a User-Agent SQLi
probe, over-cap body-prefix inspection, an offline config validator, relay
SSRF hardening + optional admin auth, and new fuzz targets. See
[CHANGELOG.md](CHANGELOG.md) for the full list,
[THREAT_MODEL.md](THREAT_MODEL.md) for what the WAF is and is not designed
to catch, and [docs/configuration.md](docs/configuration.md) for the
Middleware config reference. The webhook protocol contract lives in
[docs/webhook-protocol.md](docs/webhook-protocol.md).

## What it does

`purple-wolf` inspects every HTTP request reaching a route protected by one
of its Middlewares and either lets it through or returns `403 Forbidden`.
Inspection covers headers, URL, query parameters, and the request body (up
to a configurable cap) using a hybrid engine: libinjection (SQLi/XSS),
aho-corasick literal signatures, structural anomaly checks, and per-IP
rate limiting / deny-listing.

## Architecture at a glance

```
internet → Traefik (TLS, routing, your existing setup)
              └─ loads purple-wolf.wasm once at startup
              └─ for each request matching a route that chains a
                 purple-wolf Middleware:
                   instantiate plugin with that Middleware's config
                   → inspect → allow or block → forward to backend
```

- Three crates:
  [`purple-wolf-core`](crates/purple-wolf-core) (the engine, pure Rust,
  native + `wasm32-wasip1`),
  [`purple-wolf-traefik`](crates/purple-wolf-traefik) (http-wasm guest
  plugin), and (v0.3+)
  [`purple-wolf-relay`](crates/purple-wolf-relay) — a standalone
  webhook fan-out service that tails Traefik's audit-log stream and
  delivers HMAC-signed events to subscribers.
- Multi-tenant by construction: each `Middleware` CRD is a separate plugin
  instantiation with its own slice of WASM memory.
- **Push delivery (v0.3+):** the WAF stays focused on detection; if you
  want signed webhooks to a SIEM, Slack, or per-tenant subscriber, run
  the relay alongside Traefik. See the relay's
  [README](crates/purple-wolf-relay/README.md) and the
  [webhook protocol spec](docs/webhook-protocol.md).

## Quick start

### Local demo

Run Traefik, the WASM plugin, a backend, the relay, and an HMAC-verifying
subscriber:

```bash
docker compose -f examples/demo/docker-compose.yml up --build
```

Then try the requests in [`examples/demo/README.md`](examples/demo/README.md).

### Kubernetes install

Install the OCI Helm chart in monitor mode:

```bash
helm install purple-wolf oci://ghcr.io/guaracloud/charts/purple-wolf \
  --version <version> \
  -f charts/purple-wolf/values.monitor.yaml
```

Kustomize users can start with:

```bash
kubectl apply -k deploy/kubernetes/overlays/monitor-mode
```

The chart and Kustomize overlays render monitor/enforce Middleware examples but
do not attach them to any route. Attach `purple-wolf-monitor` to selected
IngressRoutes first, review audit output, then opt in to enforce mode.

### Verify release artifacts

Before production use, verify checksums, Cosign signatures, SBOMs, image
digests, and the release manifest:

```bash
gh release download <version> --repo guaracloud/purple-wolf --dir purple-wolf-release
```

Follow [`docs/release-verification.md`](docs/release-verification.md) and deploy
digest-pinned image references from `release-manifest.json`.

### Relay operation

Run the relay when you want signed webhooks to a SIEM, Slack bridge, or tenant
subscriber. See [`docs/operations.md`](docs/operations.md),
[`docs/helm.md`](docs/helm.md), and
[`docs/kubernetes-production.md`](docs/kubernetes-production.md).

For the full per-field Middleware reference, see
[`docs/configuration.md`](docs/configuration.md). Existing raw files under
[`examples/`](examples/) remain educational examples; production users should
prefer Helm or Kustomize.

## Benchmark — head-to-head with Coraza, on the same cluster

Same Kubernetes topology, same Traefik v3.1, same backend, same
200 m CPU / 1 GiB resource budget, same OWASP CRS corpus — only the
WAF engine differs. Two rounds; round 2 expanded the matrix to a no-
WAF baseline pod, a ramp-to-break sweep, 12 CRS attack classes
(4 536 vectors), a 10-minute soak with resource sampling, and a
small functional robustness suite.

Headline results (full methodology + tables + caveats in
[`docs/benchmark.md`](docs/benchmark.md)):

- **Isolated WAF overhead: +0.1–0.2 ms p99** vs a Traefik-only baseline
  pod. Invisible at typical backend latencies.
- **Sustained throughput at the same resources:** purple-wolf is
  clean to ~8 000 RPS; Coraza http-wasm collapses at 500 RPS. About
  **16–20× more sustained RPS** for purple-wolf at the tested
  ceiling.
- **Detection across 12 CRS rule classes (4 536 vectors):**
  purple-wolf **14.55 %** overall TPR vs Coraza inline-PL1
  **6.11 %** — **2.4× more attacks blocked**, with **0 %** FPR on
  the benign corpus for both. Java (+26.5 %), RCE (+6.3 %), XSS
  (+5.1 %) are the biggest margins.
- **Memory under sustained load:** stable in an 80–96 MiB band over
  a 10-minute soak at 1 000 RPS, no drift. Coraza peaked at
  946 MiB during round 1 (OOM-killed five times at the original
  512 MiB ceiling).
- **Documented detection gaps**, both surfaced from the benchmark
  and propagated into the threat model and config docs: User-Agent
  SQLi with a `Mozilla/` prefix is not blocked; bare `;wget` in
  query strings is not blocked. See
  [`THREAT_MODEL.md §3.2.1`](THREAT_MODEL.md).

The benchmark is reproducible end-to-end:
[`benchmarks/runner/round2/run-all-round2.sh`](benchmarks/runner/round2/run-all-round2.sh).
Raw JSONL + CSV outputs from the published runs live under
[`benchmarks/results/`](benchmarks/results/).

**What the benchmark is not:** a claim that purple-wolf is "better"
than Coraza. Coraza's *native* (Go-binding) Traefik integration is
faster and rule-richer than the http-wasm path measured here, and
full OWASP CRS catches far more atomic-token tests than either
engine in this comparison — at higher FPR. The comparison is
honestly bounded: same plugin shape, same resource ceiling, same
yardstick.

## Building and testing

```bash
cargo test --workspace                   # unit + property + corpus tests
cargo clippy --workspace --all-targets   # lint
cargo build -p purple-wolf-traefik --target wasm32-wasip1 --release
```

WASM builds require `wasi-sdk`. macOS arm64 dev setup:
```bash
# Download wasi-sdk from https://github.com/WebAssembly/wasi-sdk/releases
export WASI_SDK_PATH=/path/to/wasi-sdk
```

## License

Dual-licensed under MIT OR Apache-2.0. libinjection (vendored C) is BSD-3-Clause.
