# purple-wolf

A fast, low-memory Web Application Firewall delivered as a Traefik plugin.

**Status:** v0.3 in development (audit labels + webhook relay). See
[THREAT_MODEL.md](THREAT_MODEL.md) for what the WAF is and is not designed
to catch, and [docs/configuration.md](docs/configuration.md) for the
Middleware config reference. The new webhook protocol contract lives in
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

## Quick start (Traefik)

1. **Get the plugin binary.** Download `purple-wolf.wasm` from the [latest
   GitHub Release](https://github.com/guaracloud/purple-wolf/releases),
   or build it yourself:
   ```bash
   WASI_SDK_PATH=/opt/wasi-sdk cargo build --release \
     -p purple-wolf-traefik --target wasm32-wasip1
   # artifact: target/wasm32-wasip1/release/purple_wolf_traefik.wasm
   ```

2. **Install the plugin into Traefik** (one-time, platform level).
   Place the file at `/plugins-local/src/github.com/guaracloud/purple-wolf/purple-wolf.wasm`
   in your Traefik pods, and declare it in `traefik.yml`:
   ```yaml
   experimental:
     localPlugins:
       purpleWolf:
         moduleName: github.com/guaracloud/purple-wolf
   ```

3. **Apply a Middleware** in your namespace. Start with monitor mode:
   ```bash
   kubectl apply -f examples/middleware-monitor.yaml
   ```
   See [`examples/`](examples/) for the full set:
   - [`middleware-strict.yaml`](examples/middleware-strict.yaml) — block SQLi/XSS, log everything.
   - [`middleware-monitor.yaml`](examples/middleware-monitor.yaml) — log-only rollout.
   - [`middleware-routes.yaml`](examples/middleware-routes.yaml) — attaching different policies to different routes.

4. **Reference the Middleware** in your IngressRoute (`middlewares: [{ name: purple-wolf-monitor }]`).

5. **Tune false positives for ~1 week**, then flip `mode: enforce` and let it
   block.

For the full per-field configuration reference, see
[`docs/configuration.md`](docs/configuration.md). For a runnable
end-to-end smoke test on a real Kubernetes cluster (WAF + relay +
webhook subscriber in one Pod), see
[`docs/homelab-test.md`](docs/homelab-test.md).

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
