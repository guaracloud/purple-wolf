# purple-wolf v0.2 — Design Spec

**Date:** 2026-05-24
**Status:** Approved design, pending spec review
**Supersedes:** `2026-05-22-purple-wolf-waf-design.md` (v0.1 sidecar design)
**Repository (current):** `guaracloud-purple-wolf` — to be renamed `purple-wolf`

## 1. Summary

`purple-wolf` v0.2 is a fast, low-memory Web Application Firewall delivered as a
**Traefik plugin (WASM, via the http-wasm ABI)**. The plugin loads once into a
shared Traefik HA deployment and is configured per-tenant by referencing a
Traefik `Middleware` CRD — so customers of a managed platform (the primary
target: Guara Cloud) can opt into protection through middleware references
without operating the WAF themselves.

The v0.2 redesign exists because v0.1 was a per-app-pod sidecar. That topology
assumes the application owner controls the pod spec and can't be used in a
multi-tenant managed Traefik where tenants only configure middlewares. v0.1 also
fell short of the testing rigor an open-source WAF needs.

### Goals

- **Primary deployment target:** Traefik WASM plugin, configured by referencing
  a per-tenant `Middleware` CRD. The plugin instance loads platform-wide once;
  each Middleware instantiation is independently configured.
- **Same detection promise as v0.1:** hybrid engine (libinjection-backed
  SQLi/XSS + aho-corasick signatures + structural anomaly checks + per-IP
  reputation/rate-limit), inspecting headers + URL + request body up to a
  configurable cap.
- **OSS-grade quality bar:** fuzz, property tests, vendored OWASP CRS payload
  corpus replay, criterion benchmarks with regression gates, multi-target CI
  matrix, supply-chain scanning, public-API rustdoc, semver release process,
  dual MIT/Apache-2.0 license.
- **Reusable core:** detection engine, config schema, normalization, and policy
  live in a separately-published `purple-wolf-core` crate that a future sidecar
  build (v0.3+) can wrap without rewrites.
- **Vendor-neutral naming and positioning** so the project lands as a credible
  general-purpose Traefik WAF, not a guaracloud-specific tool.

### Non-goals (v0.2)

- A sidecar binary, a Kubernetes Deployment manifest, or any deployment story
  outside a Traefik plugin. (v0.3 returns to the sidecar.)
- Cluster-wide shared rate-limit state. Rate-limit state lives in WASM linear
  memory per plugin instance per Traefik pod; effective cluster rate is
  `configured × pod_count`. Documented; a shared-state backend is a future
  feature.
- TLS termination, routing, cert management — Traefik owns all of this.
- Custom Prometheus metrics endpoint. http-wasm has no host metrics export;
  v0.2 emits per-rule-group hit counts as structured log fields, and relies on
  Traefik's built-in per-middleware metrics for request count and latency.
- Per-host / per-path overrides inside the plugin config — Traefik's native
  per-route Middleware attachment replaces them.

## 2. Architecture & Topology

### 2.1 Workspace shape

A new vendor-neutral Cargo workspace, two crates:

```
purple-wolf/
├── Cargo.toml                 (workspace)
├── crates/
│   ├── purple-wolf-core/      pure detection engine, std-WASI compatible
│   └── purple-wolf-traefik/   WASM plugin: http-wasm guest, wraps core
├── tests/
│   ├── corpus/                vendored OWASP CRS payload corpus
│   ├── fuzz/                  cargo-fuzz targets and seed corpus
│   └── parity/                detection golden-file tests
├── benches/                   criterion benchmarks (workspace)
├── examples/                  tenant Middleware YAML examples
├── docs/
└── .github/workflows/         CI matrix
```

### 2.2 Deployment model

```
┌────────────────────────────────────────────────────────────────┐
│ guaracloud orchestrator                                        │
│   • installs purple-wolf.wasm into platform Traefik (one-time) │
│   • generates per-tenant Middleware CRDs from UI/API choices   │
└────────────────────────────────────────────────────────────────┘
                                  │
                                  │ kubectl apply
                                  ▼
        ┌────────────────────────────────────────┐
        │ Tenant ACME's namespace                │
        │   Middleware "strict"  → purpleWolf {...}  │
        │   Middleware "loose"   → purpleWolf {...}  │
        │   IngressRoute /admin  → middlewares: [strict]│
        │   IngressRoute /api    → middlewares: [loose] │
        └────────────────────────────────────────┘
                                  │
                                  │ referenced by request routing
                                  ▼
internet → Traefik HA (3+ replicas, platform-managed)
              ├─ loads purple-wolf.wasm ONCE at startup
              └─ per request matching a route that chains a
                 purple-wolf Middleware:
                   instantiate plugin with that Middleware's config
                   → inspect (URL + headers + body up to cap)
                   → allow (continue to backend) | block (403)
```

Each `Middleware` is a separate plugin instantiation with its own slice of WASM
linear memory; tenants and routes are isolated by construction. Tenants never
see the plugin binary; they only write (or have the orchestrator generate)
Middleware YAML.

### 2.3 Why WASM, why not Yaegi or external ForwardAuth

- **Yaegi plugins** are interpreted Go and are exactly the performance problem
  Coraza demonstrated. Disqualified.
- **External ForwardAuth** is a network hop and only exposes headers and the
  URL — no request-body inspection, so it can't catch payload-borne attacks.
  Insufficient for a real WAF.
- **WASM plugins via http-wasm** run compiled `wasm32` code inside Traefik's
  `wazero` runtime. Compiled-language performance, sandboxed, full request
  (incl. body) access via the http-wasm guest ABI, multi-tenant by design
  (one instantiation per Middleware). This is the only Traefik plugin model
  that satisfies all four constraints (performance, multi-tenant, body
  inspection, no extra ops surface).

## 3. Per-Crate Design

### 3.1 `purple-wolf-core`

Pure Rust, `std`-only (WASI-compatible subset), no I/O, no network, no async.
The detection engine, plus everything it needs to produce a `Decision` from a
fully-built `Request` view.

| Module | Responsibility | Notes / v0.1 carry-over |
|---|---|---|
| `request` | `Request` view: method, host, path, query params (decoded), headers (lowercased), source IP, body (up to cap), `body_inspected` flag; helpers for percent-decoding and XFF source-IP extraction | ports `request_model.rs` + the `client_ip` helper |
| `config` | Typed config the plugin passes into the engine: `mode`, `fail_mode`, `body`, `groups`, `reputation`. Serde-derived. **No `overrides`. No `listen`/`upstream`/`metrics_listen`.** | ports `config.rs` trimmed |
| `detectors` | `Detector` trait, `Verdict`, `Engine`, the four groups (`injection`, `signatures`, `structural`, `reputation`) | ports all four detector files verbatim |
| `ffi` | `extern "C"` bindings + safe wrappers for libinjection (`is_sqli`, `is_xss`). The vendored C is built for native targets AND for `wasm32-wasip1` via wasi-sdk; the `build.rs` selects the toolchain by target | ports `ffi.rs` + `vendor/libinjection/`, build script extended |
| `policy` | `decide(verdicts, mode, group_mode) -> Decision` | ports `policy.rs` verbatim |
| `audit` | `AuditEntry` builder + JSON serialization; an `emit` function that callers wire to their preferred sink | ports the `AuditEntry` half of `observe.rs`; the Prometheus half is deleted |
| `clock` | A tiny `Clock` trait so the reputation rate-limiter doesn't hardcode `Instant::now()`. Two impls: `SystemClock` (native, std) and `HostClock` (WASM, reads time via the http-wasm host `getNowMillis()`/equivalent) | new; replaces the implicit `governor`-default-clock dependency |

**Dependencies removed vs. v0.1:** `axum`, `reqwest`, `tokio`, `hyper`,
`hyper-util`, `bytes` (replaced with `Vec<u8>`/`&[u8]`), `notify`, `arc-swap`,
`metrics`, `metrics-exporter-prometheus`, `tracing` (replaced with a thin
`audit::emit` callback so the host can use `tracing` if it wants — core stays
neutral).

**Rate-limit considerations:** v0.1 used `governor` with `DashMap` keyed state.
`governor` itself compiles to `wasm32-wasip1` but its default state store
(`DashMap`) and default clock both need attention. v0.2 uses `governor`'s
in-memory keyed state with a `BTreeMap`-backed store (single-threaded inside
the plugin instance) and the abstracted `Clock` trait. If `governor` proves
awkward on `wasm32`, a small token-bucket implementation in `core::reputation`
is the fallback (≤ 100 lines).

**Public API:** small and stable. The only types the plugin crate touches are
`Request::builder()`, `Config`, `Engine::new`, `Engine::inspect`,
`policy::decide`, `AuditEntry`. Everything else is internal.

### 3.2 `purple-wolf-traefik`

The host-adapter shell. Compiles to a single `purple-wolf.wasm` for
`wasm32-wasip1`.

| Module | Responsibility |
|---|---|
| `host` | http-wasm guest ABI bindings. Prefer the upstream `http-wasm-guest-rust` SDK if mature; otherwise a thin hand-rolled shim against the http-wasm spec. Provides typed accessors for the request (method, URI, headers, body), response (status, headers, body), and host services (`log`, `getNowMillis`) |
| `entry` | The http-wasm `handle_request` / `handle_response` exported functions. On `handle_request`: parse the Middleware-supplied JSON config, build a `core::Request`, run `Engine`, apply `policy::decide`. On allow: pass through. On block: write 403 + a short reason body and stop further processing. Emit an `AuditEntry` via the host `log` call when the request had any verdicts |
| `config` | Deserialize the Traefik Middleware plugin params (JSON delivered by the host) into `core::config::Config`. Adapter handles the camelCase ↔ snake_case mapping |

By design this crate is small: under 1000 lines, almost all of which is the
host shim. The detection logic is in `core`.

**Build target:** `wasm32-wasip1` (mature, well-supported). If the http-wasm
SDK matures around `wasm32-wasip2` (component model) before v0.2 ships, we
revisit; the spec doesn't lock to wasip1 forever.

## 4. Middleware Config Schema — The Orchestrator-Facing API

This is the v0.2 public API contract; semver applies.

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: customer-strict
  namespace: tenant-acme
spec:
  plugin:
    purpleWolf:
      mode: enforce                    # enforce | monitor       (required)
      failMode: failOpen               # failOpen | failClosed   (default failOpen)
      body:
        maxInspectBytes: 1048576       # default 1 MiB
        overCap: pass                  # pass | block            (default pass)
      groups:
        injection:  { enabled: true,  mode: enforce }   # SQLi + XSS via libinjection
        signatures: { enabled: true,  mode: enforce }   # known-bad literal set
        structural: { enabled: true,  mode: monitor }   # method/header anomaly
        reputation: { enabled: true,  mode: enforce }   # rate limit + IP deny
      reputation:
        perSecond: 100
        denyList: ["203.0.113.7"]
```

**Field semantics:**

- `mode` (global) — `monitor` never blocks anything regardless of group config;
  `enforce` allows per-group enforcement.
- `failMode` — applies to soft failures (detector error or decoding error
  inside the plugin). Process-death is inherently fail-closed in the sense
  that Traefik will fall back to whatever its `failure` directive specifies
  for plugin failures (typically the route fails). Documented.
- `body.overCap` — `pass` means oversized bodies are forwarded uninspected.
  Note: a Traefik WASM plugin currently does not get streaming access to the
  request body in the way the v0.1 sidecar did via reqwest; the http-wasm ABI
  exposes the body as bytes up to a host-configured limit. v0.2 inspects up
  to `maxInspectBytes` and lets Traefik pass the rest through normally —
  Traefik handles the actual streaming. `block` returns 403 if the host
  reports the body exceeded `maxInspectBytes`.
- Per-group `enabled` + `mode` — same semantics as v0.1.
- `reputation.perSecond` — token-bucket quota per source IP, per plugin
  instance per Traefik pod. Cluster-effective rate = `perSecond × pod_count`,
  documented.

**Naming conventions:**

- Middleware YAML uses **camelCase** (Traefik plugin convention so it reads
  naturally next to other middleware specs).
- Core's internal Rust types stay **snake_case** (Rust convention). The
  `purple-wolf-traefik::config` module adapts.

**Source IP:**

The plugin always derives source IP from `X-Forwarded-For` (first valid
`IpAddr` in the comma-separated list) → `X-Real-IP` → the host-reported
connection peer. Not user-configurable. Operators are expected to configure
Traefik's `trustedIPs` on the entrypoint so XFF is trusted.

**Audit log:**

One JSON object per noteworthy request (a request that produced at least one
verdict, regardless of action) emitted via the http-wasm host `log()` call.
Standard log collectors (Loki, Promtail, Fluent Bit) pick it up via Traefik's
log stream. Fields: `host`, `path`, `query`, `method`, `sourceIp`, `action`,
`blockedRule`, `blockedSeverity`, `blockedDetail`, `wouldBlockRules`.

**Metrics:**

- Traefik's built-in per-middleware metrics give per-Middleware request count
  and latency for free.
- Per-rule-group hit counts are emitted as structured fields on the audit
  log; operators turn these into metrics via Loki `metric_query`/equivalent.
- No custom Prometheus endpoint (impossible from a sandboxed WASM plugin
  without a host extension; deferred to a future plugin/sidecar variant).

## 5. Testing, Benchmarking, Release — The OSS-Grade Bar

### 5.1 Tests (`cargo test --workspace`)

- Unit tests per `core` module (port and extend v0.1's).
- `proptest`-based property tests for:
  - normalization idempotence (decoding twice equals decoding once)
  - monitor mode never produces a `Block` action
  - `GroupMode::Off` suppresses all verdicts in that group
  - `client_ip` falls back consistently across all permutations of XFF /
    X-Real-IP / peer
- Detection parity / golden-file tests against a vendored payload corpus
  drawn from the **OWASP CRS regression test suite** (CRS v3.x
  `tests/regression/`) plus the public `nuclei` SQLi/XSS templates. Any
  allow-listed false positive must come with a written justification
  comment.

### 5.2 Fuzz (`cargo fuzz`)

Targets:

- `request_parser` — random bytes into `Request::builder()` must never panic
  and must produce a normalized view in bounded time.
- `injection_inspect` — random UTF-8 fields through `InjectionDetector`.
- `signatures_inspect` — random ASCII through `SignatureDetector`.
- `policy_decide` — random `Vec<Verdict>` + modes through `decide`.

CI runs each target time-bounded (30s wall clock); the seed corpus is
committed and grows organically.

### 5.3 Benchmarks (`criterion`, in `benches/`)

- Per-detector latency on a small representative request.
- End-to-end pipeline (build `Request` → `Engine::inspect` → `decide`) on
  the same.
- A CI job compares against the main-branch baseline and **fails the PR on
  > 10% regression** unless explicitly waived in the commit message.

### 5.4 CI matrix (GitHub Actions)

| Job | What it runs |
|---|---|
| `test-linux` | `stable / beta / 1.75 (MSRV)` × `cargo test --workspace` |
| `test-macos` | `stable` × `cargo test --workspace` |
| `lint` | `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` |
| `supply-chain` | `cargo deny check licenses bans advisories` |
| `wasm-build` | `cargo build -p purple-wolf-traefik --target wasm32-wasip1`, plus a wasi-sdk-backed C build to confirm libinjection compiles to WASM |
| `fuzz-smoke` | each fuzz target run for 30 seconds against the seed corpus |
| `bench-regression` | criterion run vs. baseline, fail on > 10% regression |
| `coverage` | `cargo llvm-cov --workspace`, fail if `purple-wolf-core` coverage drops below 80% |
| `docs` | `cargo doc --workspace -D warnings` |
| `traefik-integration` | spin up a real Traefik in Docker with the built `.wasm` mounted; exercise sample Middlewares via `curl` and assert WAF behavior |

### 5.5 Release

- Repo + crates renamed from `guaracloud-purple-wolf` to `purple-wolf`.
- Dual-licensed **MIT OR Apache-2.0** (Rust convention).
- `purple-wolf-core` published to crates.io.
- `purple-wolf-traefik` not published to crates.io; the `purple-wolf.wasm`
  artifact (plus its SHA256 + a cosign signature) attaches to each GitHub
  Release.
- Releases driven by `cargo-release` from a `release/v*` branch; semver
  applies to `purple-wolf-core`'s public API and to the Middleware config
  schema.
- README, CONTRIBUTING, CHANGELOG (keep-a-changelog), CODE_OF_CONDUCT,
  SECURITY.md (private vulnerability reporting), full rustdoc for the
  public `purple-wolf-core` API including runnable examples.

## 6. Migration from v0.1

The `feat/purple-wolf-impl` branch stays on the repo as a reference; v0.2
work begins fresh from `main`.

| v0.1 file/component | v0.2 fate |
|---|---|
| `src/config.rs` | → `core::config`, trimmed (no `overrides`, no `listen`, no `upstream`, no `metrics_listen`) |
| `src/request_model.rs` + `client_ip` helper | → `core::request` |
| `src/detectors/*` (engine + 4 groups) | → `core::detectors`, verbatim port |
| `src/ffi.rs` + `vendor/libinjection/` + `build.rs` | → `core::ffi`, build script extended for the `wasm32-wasip1` target via wasi-sdk |
| `src/policy.rs` | → `core::policy`, verbatim |
| `src/observe.rs` (`AuditEntry`) | → `core::audit`; the Prometheus `record_request` half deleted |
| `src/rules.rs` (hot-reload, overrides, ArcSwap) | **deleted** — host owns config lifecycle |
| `src/proxy.rs` | **deleted** — host owns the data path |
| `src/main.rs` (axum bootstrap) | **deleted** |
| `tests/integration.rs` | **deleted** — replaced by a Traefik-in-Docker integration suite |
| `deploy/Dockerfile` + `deploy/sidecar-example.yaml` | **deleted** — return in v0.3 sidecar |
| `Cargo.toml` (single-crate) | replaced by a workspace `Cargo.toml` + two crate manifests |

## 7. Error Handling

- Plugin entry points (`handle_request`, `handle_response`) catch any internal
  error (decoder failure, config-parse failure on the first call, detector
  panic via `catch_unwind`) and apply `failMode`. `failOpen` → continue to
  backend; `failClosed` → 403.
- A first-call config-parse failure is logged via the host log call at
  `error` level; the host's plugin-failure directive then applies.
- libinjection FFI continues to treat its `ERROR = -1` return as benign
  (documented fail-open), same as v0.1.

## 8. Observability

- **Audit log** — JSON per noteworthy request, via host `log()`. Captured by
  Traefik's log stream.
- **Traefik built-in metrics** — `traefik_router_*`, `traefik_middleware_*`
  per Middleware: request count, latency, status. No code change needed.
- **Group hit counts** — emitted as fields on the audit-log JSON; Loki /
  Promtail / Vector users can derive Prometheus metrics from these.

## 9. Open Items for Implementation Planning

- Exact `http-wasm-guest-rust` SDK version and maturity assessment (vs.
  hand-rolling the shim against the http-wasm spec).
- `wasi-sdk` version pin for the libinjection cross-compile and how it's
  consumed in `build.rs` (downloaded by the build vs. pre-installed on CI).
- `governor` viability on `wasm32-wasip1`; fallback to a tiny in-core
  token-bucket if it doesn't compile cleanly.
- Whether `wasm32-wasip1` or `wasm32-wasip2` is the right target at
  implementation time (depends on Traefik's wazero version).
