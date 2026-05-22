# purple-wolf — Design Spec

**Date:** 2026-05-22
**Status:** Approved design, pending spec review
**Repository:** `guaracloud-purple-wolf`
**Binary / tool name:** `purple-wolf`

## 1. Summary

`purple-wolf` is a custom Web Application Firewall written in Rust, deployed as a
per-application-pod sidecar behind Traefik. It exists because Coraza + OWASP CRS
is too heavy for the `guaracloud` ingress on three axes simultaneously: per-request
latency, CPU cost, and RAM footprint. `purple-wolf` replaces the
~200-PCRE-regex CRS model with a hybrid detection engine that is fast and
low-memory by construction.

### Goals

- Add **< 0.5 ms p99** latency per request.
- Hold **< 30 MiB** RSS per sidecar at idle, **< 64 MiB** under load.
- Ship a **minimal static binary and container image** (target: single-digit-MB
  image, statically linked, scratch/distroless base).
- Inspect full request bodies, not just headers/path/query.
- Let operators enable/disable and tune individual rule groups, globally and
  per-host/per-path.
- Support a monitor (log-only) rollout mode and a configurable fail mode.

### Non-goals (v1)

- TLS termination (Traefik keeps doing this).
- Routing / service discovery (Traefik keeps doing this).
- Cluster-wide shared state (rate limiting is per-instance in v1).
- A management UI or dynamic rule API — config is file/ConfigMap driven.

## 2. Topology & Process Model

`purple-wolf` runs as a sidecar container in each application pod, in the "B2"
position — *behind* Traefik, in the request data path:

```
internet → Traefik (TLS termination, routing, cert-manager)
              ↓ routes to the app's Kubernetes Service
         Service.targetPort → purple-wolf sidecar :8080   ← inspects plaintext + body
              ↓ localhost
         app container :3000
```

Traefik configuration is **unchanged**. The only per-app Kubernetes change:

- The app's `Service` `targetPort` points at the `purple-wolf` container port.
- `purple-wolf`'s configured upstream is `localhost:<app-port>`.

### Rationale for this topology

- **TLS:** Traefik already terminates TLS via cert-manager. Placing the WAF in
  front (B1) would force it to either terminate TLS itself (large scope creep,
  private keys in custom code) or pass ciphertext through (blind, useless).
  Behind Traefik, `purple-wolf` receives clean plaintext HTTP.
- **No routing replication:** As an app-pod sidecar, the WAF's only upstream is
  `localhost`. It never needs to reproduce Traefik's routing table.
- **Blast radius:** A WAF bug takes down one app, not the whole ingress edge.
- **RAM distribution:** Memory cost is spread across app pods rather than
  concentrated in Traefik pods. The shared rule data is mmap'd read-only so each
  instance's private RSS stays small.

### Implementation base

Rust, async, built on `hyper` + `tokio`. A small fixed worker pool. The hot path
(parse → inspect → forward) avoids per-request heap allocation where practical
(reused buffers, `bytes::Bytes` slices).

## 3. Internal Components

Each component is an independently testable unit with a defined interface.

| Unit | Responsibility | Depends on |
|---|---|---|
| `proxy` | Accept HTTP from Traefik, stream request to the `localhost` upstream, stream the response back. Owns connection handling and body buffering. | `hyper` |
| `request model` | Build a single normalized, decoded view of the request: URL-decode, lowercase where relevant, strip, de-duplicate parameters, decode known evasion encodings. Evasion resistance lives here. | — |
| `detectors` | The hybrid detection engine (see §4). Pure functions over the request model returning verdicts. | `request model` |
| `rules` | Load rule-group config and per-host/path overrides from an mmap'd file; hot-reload on change via `inotify`. | `notify` crate |
| `policy` | Combine detector verdicts into a single action, applying global mode, per-group mode, and fail mode. | `detectors`, `rules` |
| `observe` | Expose a Prometheus `/metrics` endpoint and emit a structured JSON audit log per decision. | — |

## 4. Hybrid Detection Engine

Four detector classes, each exposed as an independently toggleable rule group.

### 4.1 `injection` — SQLi & XSS

Uses the battle-tested C library **libinjection** via a Rust FFI binding. This is
a tokenizer-based detector (not regex), with a low false-positive rate and proven
detection quality. The FFI boundary is a single small, well-contained `unsafe`
surface; libinjection itself is ~2k lines of audited C.

### 4.2 `signatures` — known-bad literals

Uses the `aho-corasick` crate to build one automaton matching all known-bad
literal strings in a single pass: path traversal sequences, RCE payload
fragments, known scanner User-Agents. Pure Rust, low RAM, no regex backtracking.

### 4.3 `structural` — anomaly checks in code

Plain Rust logic, no patterns: body/header size caps, HTTP method allowlist,
header-count and header-size anomalies, malformed or double encoding.

### 4.4 `reputation` — rate limiting & IP lists

Per-instance in-memory token-bucket rate limiting via the `governor` crate, plus
static IP allow/deny lists. State is **local to each sidecar** in v1; no shared
Redis. Cluster-wide limits are explicitly deferred (YAGNI until needed).

## 5. Body Handling — RAM Control Point

Request bodies are streamed with a **configurable inspection cap**
(`body.max_inspect_bytes`, default 1 MiB):

- Body under the cap → fully buffered and inspected.
- Body over the cap → behavior is configurable (`body.over_cap`): `block` the
  request, or `pass` it through uninspected.

This gives a hard, predictable per-instance RAM ceiling independent of traffic
shape, and is the primary lever for the < 64 MiB target.

## 6. Configuration Model

Configuration is delivered as a Kubernetes ConfigMap, mounted as a file, mmap'd
read-only by `purple-wolf`, and hot-reloaded on change via `inotify` (no pod
restart required).

```toml
mode = "monitor"        # monitor | enforce   — global rollout switch
fail_mode = "fail_open" # fail_open | fail_closed

[body]
max_inspect_bytes = 1048576
over_cap = "pass"       # pass | block

[groups.injection]   { enabled = true,  mode = "enforce" }
[groups.signatures]  { enabled = true,  mode = "enforce" }
[groups.structural]  { enabled = true,  mode = "monitor" }
[groups.reputation]  { enabled = false }

# per-host / per-path overrides
[[overrides]]
host = "api.guaracloud.com"
path_prefix = "/webhooks/"
disable_groups = ["reputation"]
```

- Every rule group can be independently **enabled/disabled** and given its own
  **mode** (`enforce` / `monitor` / `off`).
- `overrides` entries scope group changes to a host and/or path prefix.
- A group's effective mode is the per-group mode, unless globally `mode` is
  `monitor`, in which case nothing blocks regardless of group settings.

## 7. Operational Behavior

### 7.1 Rollout — monitor mode

`mode = "monitor"` ships first. Every would-block verdict is logged with full
detail (matched group, rule, request fingerprint) but **nothing is blocked**.
Operators tune false positives against real `guaracloud` traffic, then flip
groups to `enforce` one at a time.

### 7.2 Fail mode

`fail_mode` governs **per-request internal failures** — detector error,
detection timeout, overload / queue-full:

- `fail_open` → forward the request uninspected.
- `fail_closed` → return 403.

**Honest caveat:** because `purple-wolf` is in the request data path, **total
process death is inherently fail-closed** — if the sidecar process is dead, the
Service target is dead and the app is unreachable. No configuration changes this.
`fail_open` only mitigates *soft* failures. Mitigations for hard failure:

- Kubernetes liveness probe + fast restart.
- Per-request panic isolation via `catch_unwind`, so a single malformed request
  can never kill the process.

## 8. Error Handling

- Every request is processed inside `catch_unwind`; a panic becomes a per-request
  failure subject to `fail_mode`, never a process crash.
- Upstream (`localhost` app) connection errors are surfaced as 502, distinct
  from WAF-originated 403s.
- Config file parse errors on hot-reload are logged and the **previous valid
  config is retained** — a bad ConfigMap edit never degrades protection.
- Detection timeouts are bounded per request and counted as soft failures.

## 9. Observability

- **Prometheus `/metrics`**: request count, decision count by action/group,
  added-latency histogram, body-cap-exceeded count, soft-failure count, RSS.
  Scraped via the existing `ServiceMonitor` pattern used in the cluster.
- **Structured JSON audit log**: one line per blocked or would-block decision —
  timestamp, host, path, method, source IP, matched group + rule, verdict,
  effective mode.

## 10. Performance & Size Targets

| Target | Value |
|---|---|
| Added latency (p99) | < 0.5 ms |
| RSS at idle | < 30 MiB |
| RSS under load | < 64 MiB |
| Container image | single-digit MB, scratch/distroless base |
| Binary | static, stripped |

Binary/image minimization techniques (release profile):
`opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`,
`strip = true`; statically linked (`x86_64-unknown-linux-musl`) so the container
can be `FROM scratch` plus the single binary and CA certs.

## 11. Testing Strategy

- **Unit tests per detector** against a payload corpus: SQLi/XSS evasion sets,
  relevant OWASP CRS test cases, `nuclei` template payloads. Each detector is a
  pure function over the request model, so tests need no network.
- **Integration tests** through the full `proxy` → `policy` path against a stub
  upstream, covering allow / block / monitor / fail-open / fail-closed and
  config hot-reload.
- **Benchmark harness** measuring added p99 latency and peak RSS against the
  §10 targets; run in CI as a regression gate.

## 12. Proposed Crate Choices

| Concern | Crate / library |
|---|---|
| HTTP server + client/proxy | `hyper`, `tokio` |
| SQLi / XSS detection | `libinjection` (C) via FFI |
| Multi-literal matching | `aho-corasick` |
| Rate limiting | `governor` |
| Config file watch / hot-reload | `notify` |
| Metrics | `metrics` + Prometheus exporter |
| Config parsing | `toml`, `serde` |

## 13. Open Items for Implementation Planning

- Exact Rust FFI binding strategy for libinjection (`bindgen` vs. hand-written
  `extern` block + vendored C built with `cc`).
- Whether `purple-wolf` listens HTTP/1.1 only or also HTTP/2 from Traefik.
- ConfigMap reload debounce interval.
