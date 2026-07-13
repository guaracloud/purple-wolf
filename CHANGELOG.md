# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.5] - 2026-07-13

### Performance

- Bound literal-signature verdict allocation to one finding per static pattern
  per request, and use hashed membership for reputation deny lists above the
  small-list threshold while retaining the linear path for small/default lists.
- Align the relay's direct `rand` dependency with the version already used by
  `ulid`, removing a duplicate `rand`/`rand_core`/`rand_chacha` stack.

### Fixed

- Supervise relay source, parser, pipeline, and admin tasks so unrecoverable
  failures clear readiness, stop the remaining task graph, and propagate to the
  process instead of leaving a ready-but-inert relay waiting for a signal.
- Isolate `origin/main` and pull-request Cargo target directories in benchmark
  CI, copying only Criterion's saved measurements between them so compiled
  artifacts cannot be reused across different worktrees.
- Accept the documented `ip:port` and bracketed IPv6-with-port forms in
  `reputation.denyList` instead of silently dropping them during detector setup.
- Replace wall-clock relay integration polling with bounded process-exit and
  drain synchronization plus captured diagnostics, eliminating slow-run races.

### Changed

- Move GitHub release uploads to the Node 24-based
  `softprops/action-gh-release` v3.0.1 runtime.

## [0.4.4] - 2026-07-10

### Security

- Update `quinn-proto` to 0.11.15 in the workspace and fuzz lockfiles,
  resolving `RUSTSEC-2026-0185`, and synchronize the fuzz lockfile with the
  existing `anyhow` 1.0.103 fix. Replace the placeholder vulnerability-reporting
  address with Guara Cloud's published contact, retain private GitHub Security
  Advisories as the preferred channel, and correct the supported release line
  and signed WASM artifact name.

### Performance

- Make TOML parsing a default-on `purple-wolf-core` feature and disable it for
  the JSON-only Traefik guest, removing the TOML parser stack from WASM builds.
  Default users retain `Config::parse`; embedders that disable default features
  must enable `toml-config` when they need that method.
- Avoid a heap allocation while deriving SQLi suffix probes from ordinary
  browser User-Agent values, preserving the existing candidate order and
  deduplication behavior.
- Remove the relay's unused dependency on `purple-wolf-core` and compile only
  the Tokio/Hyper features its HTTP/1 admin server and subscriber client use.

### Reliability

- Test and document the core crate with optional TOML support disabled in CI.
  Build benchmark baselines from an isolated `origin/main` worktree, include
  root manifest, lockfile, and toolchain changes in benchmark triggers, and use
  locked graphs. Require the committed lockfile in release, dev-image, and
  production relay-container builds.
- Add crates.io keywords/categories for publishable packages and remove an
  unmatched license allowance from `cargo-deny` configuration. Complete the
  Helm chart metadata, make workflow environment-file writes shell-safe, and
  move checkout, artifact, Pages, and Docker jobs from deprecated Node 20
  actions to their current Node 24 majors. Validate the workflow set with
  `actionlint`.

## [0.4.3] - 2026-07-10

### Security

- Pin active demo, integration, and homelab Traefik images to v3.7.7, outside
  the affected range of the 2025 WASM plugin archive path-traversal advisory.
  Historical benchmark manifests remain on v3.1 so published results stay
  reproducible.

### Performance

- Compile the request-path core and Aho-Corasick matcher at `opt-level = 3`
  while retaining size optimization for the rest of the workspace. Controlled
  Criterion runs improved representative inspection cases by 17-23% for a
  3.1% WASM size increase.
- Keep common http-wasm ABI scratch buffers on the stack, reuse valid UTF-8
  host buffers as `String`s, and join duplicate headers without intermediate
  strings.
- Add relay parser benchmarks and avoid allocating ANSI-normalized copies for
  plain log lines; brace-free non-audit lines now reject before normalization.

### Reliability

- Clamp `body.maxInspectBytes` to the host's existing 16 MiB guest allocation
  ceiling with an operator-visible warning instead of silently inspecting less
  than the parsed configuration advertises.
- Make the full relay integration harness portable across Linux and macOS by
  building the production distroless image, accepting a prebuilt WASM, and
  allowing host ports to be overridden without disrupting unrelated services.

## [0.4.2] - 2026-07-09

### Security

- Negotiate http-wasm request buffering and inspect bodies regardless of
  Content-Length framing. Fixed-length and chunked request bodies are now
  preserved byte-for-byte for the backend, while SQLi in either framing is
  blocked consistently.
- Bound host-controlled header aggregate lengths and value counts before
  allocating guest memory, and fail closed if a body stream becomes unsafe to
  forward after reconstruction has started.
- Update `anyhow` to 1.0.103, resolving `RUSTSEC-2026-0190`.

### Performance

- Normalize owned header names in place, skip percent-decoding work for common
  header values without `%`, and resolve X-Forwarded-For without a temporary
  vector. Controlled Criterion runs measured faster request construction and
  client-IP resolution without changing normalization semantics.
- Construct only enabled detector groups and grow reputation storage from a
  small initial allocation instead of reserving 50,000 entries in every pooled
  WASM guest.

### Reliability

- Reject `relay.subscriber_queue: 0` during configuration validation instead
  of allowing Tokio channel construction to panic at startup.
- Add byte-faithful real-Traefik body regressions, prebuilt-WASM integration
  support, and an isolated homelab validation manifest.
- Make the Docker WASI builder work on arm64 hosts through an explicitly
  emulated amd64 stage, and exclude build artifacts from Docker contexts.
- Correct lifecycle, body-cap, reputation-scope, relay-durability, and
  `Retry-After` documentation to match the implemented behavior.

## [0.4.1] - 2026-06-10

### Fixed

- Keep relay `/readyz` unauthenticated even when optional admin bearer auth is
  enabled, so Kubernetes readiness probes cannot make authenticated relay pods
  permanently unready. `/metrics` and `/version` remain protected.
- Apply rustfmt to the v0.4 hardening changes so the release commit satisfies
  the CI `cargo fmt --all --check` gate.
- Refresh release, chart, Kustomize, example, and verification references that
  still pointed at v0.3/v0.4 after the v0.4.0 release.
- Remove duplicate/stale configuration docs and update relay threat-model
  language for the v0.4+ admin-auth reality.

## [0.4.0] - 2026-06-09

### Security & robustness hardening

- **O(1) reputation-limiter eviction.** The bounded per-IP token-bucket map
  previously evicted via an O(n) scan; once an attacker filled it to the cap
  by rotating source IPs, every new-IP request scanned all entries - a
  CPU-DoS lever. Replaced with an intrusive doubly-linked-list LRU over a
  fixed slab: every operation is O(1). No new dependencies.
- **Percent-decode to a bounded fixpoint** (max 3 passes) closes multi-
  encoding evasion (`%2527` → `%27` → `'`); single-pass decoders inspect the
  still-encoded form and miss the cleartext. Inspection-only; bytes forwarded
  upstream are unchanged.
- **Signature pack expansion** (precision-first, collision-aware): shell
  command injection (`;wget` `;curl` `;bash` `;nc ` `|bash` `|sh `),
  `${jndi:` (Log4Shell), `php://`/`phar://`/`expect://`, `/etc/shadow`,
  `/proc/self/environ`, `/WEB-INF/`, `xp_cmdshell`. Closes the documented
  round-2 `;wget` gap.
- **User-Agent SQLi suffix probe** closes the documented Mozilla-prefix gap:
  libinjection fingerprints `Mozilla/5.0 1 OR 1=1` as a UA string; the
  detector now re-probes the UA suffix so the isolated SQL is tokenized.
- **Structural NUL-byte and CR/LF checks** over the decoded path and query
  (LFI path-truncation and response-splitting adjacency).
- **Over-cap request bodies now inspect the buffered prefix** instead of
  discarding the whole body, closing the "prepend padding to skip body
  inspection" lever (THREAT_MODEL §4.2). New `body_truncated` audit field.
- **Panic discipline.** `wasm32-wasip1` is `panic = "abort"`, so the guest's
  `catch_unwind` never catches a detector panic (it traps the instance and
  bypasses `failMode`). Documented honestly (Cargo.toml, THREAT_MODEL §4.3)
  and enforced structurally: `deny(clippy::unwrap_used / expect_used / panic)`
  in core and traefik exclude panics from production paths.
- **`config_fallback` audit field** marks every line emitted while running on
  the all-monitor fallback (a bad Middleware config), so dashboards see that
  enforcement is silently off - not just one startup log line.
- **`purple-wolf-validate`** binary validates a plugin config offline (same
  adapter as the live guest) for operator CI.
- **Relay SSRF hardening:** the HTTP enricher now percent-encodes the
  substituted label value so it can only be an opaque path component, never
  alter the URL structure or authority.
- **Relay admin auth (optional):** bearer-token guard on `/metrics`,
  `/readyz`, `/version` (constant-time compare; `/healthz` stays open). Off by
  default with a startup warning, preserving v0.3 behavior.
- **Fuzz targets** for `client_ip` (XFF parsing) and the relay log-line
  parser, wired into the `fuzz-smoke` CI job.
- **Benign corpus widened** (~53 → ~104 lines) targeting the new signatures'
  collision boundaries; the 0%-FPR gate holds.

## [0.3.0] - 2026-05-25

### Added - v0.3 audit labels + webhook relay

- **`Config.labels: BTreeMap<String, String>`** on every Middleware. Free-form
  `key=value` metadata that the WAF echoes verbatim into every audit-log line
  for that Middleware. Keys match `^[a-z][a-z0-9_.-]{0,62}$`, ≤32 keys,
  ≤4 KiB total (BTreeMap → deterministic alphabetical JSON). The
  reserved-prefix `purple_wolf.*` is dropped at the adapter with a
  one-warning-per-key log so a tenant who copied an example can't shadow
  WAF-set fields. Value scrubbing strips ASCII control chars at audit-emit
  time (same log-injection guard as `blocked_detail`). See
  [`docs/configuration.md` § Labels](docs/configuration.md#labels).
- **`purple-wolf-relay` (new crate, `0.3.0`)** - standalone, vendor-neutral
  webhook fan-out for purple-wolf audit events. Tails Traefik's stdout (or
  stdin), parses the audit JSON, optionally enriches labels, evaluates
  per-subscriber filters (label subset / severity floor / glob rule
  pattern), and delivers HMAC-SHA256-signed POSTs with exponential backoff
  retries + bounded DLQ. Per-subscriber bounded mpsc isolates slow
  subscribers from fast ones; on-disk bookmark resume across restarts.
  Distroless multi-arch Docker image at
  `ghcr.io/guaracloud/purple-wolf-relay`. Prometheus `/metrics`,
  `/healthz`, `/readyz`, `/version`.
- **`docs/webhook-protocol.md`** - stable `purple-wolf.audit/v1` envelope
  spec (HMAC scheme, idempotency, retry semantics, versioning policy,
  reference subscriber implementations in Python / Go / TypeScript).
- **`relay-integration` CI job** runs a full-stack docker-compose
  (Traefik + WAF + relay + mock subscriber) and asserts a SQLi attack
  produces a verified HMAC-signed envelope at the subscriber with
  the operator's labels intact.

### Added - detection scope

- **Inspect allow-listed request headers** (Cookie, Referer, Host,
  Authorization, User-Agent, any `X-*` custom header) for both raw and
  percent-decoded forms. The pre-fix engine silently ignored every
  header except User-Agent - Cookie/Referer SQLi returned 200 with no
  audit-log entry. (NEW C-1, NEW-I4)
- **Raw-byte inspection end-to-end.** `Request::body` now stores raw
  bytes; FFI to libinjection takes `&[u8]`; `inspectable_fields()`
  returns `Vec<&[u8]>`. A SQLi crafted in SHIFT-JIS / GBK / any
  non-UTF-8 encoding now reaches the detector intact instead of
  being lossy-converted to U+FFFD. (NEW-I2)
- **`Groups::all_monitor()` safe fallback.** A malformed Middleware
  config now runs every detector in monitor mode (verdicts in
  `would_block_rules`) instead of disabling every detector silently.
  (NEW-C1)
- **Explicit XFF trust model** via `xff.trustedHops`. Default `0`
  ignores XFF entirely and uses the TCP peer for rate-limit /
  attribution. Operators opt in to N trusted proxies; misconfiguring
  this is a self-DoS primitive documented in THREAT_MODEL.md. (NEW-H3)
- **THREAT_MODEL.md** documenting trust boundaries, in-scope attacks,
  explicit non-goals, and operational hazards.
- **SECURITY.md** with concrete disclosure channel (GitHub Security
  Advisory + email), 72h/7d/90d SLA, and cosign verify-blob example.
- **Honest CRS extractor** parses YAML structure and honors
  `expect_ids` vs `no_expect_ids`. Recovered benign sub-corpus
  (~152 payloads) is now tested for FP rate (~7%, well under the
  bounded 0.40 ceiling). Attack-only detection re-measured at 22%
  (XSS 45%, SQLi 18%). (NEW-C2, NEW-I8)
- **Expanded `clean.txt` benign corpus** from 5 to ~66 hand-curated
  lines: query shapes, cookies, URLs, emails, tokens, JSON bodies,
  multi-byte text, programming-content snippets. Zero FP. (I-6)
- **`traefik-integration` CI job** runs the docker-compose
  end-to-end suite against the built `.wasm`, catching
  header-inspection regressions automatically.
- **`reputation.maxTrackedIps`** config field (default 50,000) caps
  the per-IP rate-limiter's memory footprint under adversarial IP
  rotation.

### Changed - invariants

- **`policy::decide` picks the blocking verdict by severity, not
  detector iteration order.** A Critical SQLi can no longer be
  shadowed in the audit log by a Medium scanner_ua verdict that
  fired first. (NEW-H1)
- **Bounded LRU rate-limiter.** Replaced `governor` with a small
  in-crate token-bucket + LRU keyed map; drops the `futures`
  transitive dependency tree from core. (NEW-H2)
- **`#[serde(deny_unknown_fields)]`** on every Wire* struct in the
  Middleware adapter; a tenant typo (`groupz:`) now surfaces at
  parse time instead of silently disabling detection. (I-2, NEW-M5)
- **Repo URL** corrected from `guaracloud-oss/purple-wolf` (404) to
  `guaracloud/purple-wolf` (the actual git remote). (C-2)
- **`AuditEntry::detail`** scrubs ASCII control characters (CR / LF /
  NUL / BEL) so attacker payloads can't fool regex-based downstream
  log parsers (Promtail / Loki / Vector). (NEW-I1)
- **Headers joined per RFC 7230** when sent multiple times; previously
  only the first value was inspected, so an attacker could hide a
  payload in a second Cookie header. (NEW-I3)
- **`de_lenient_bool`** rejects empty string `""` (was silently
  `false` - a typo trap). (NEW-M6)
- **`perSecond: 0` and `maxInspectBytes: 0`** are now parse errors
  instead of silent coercions. (NEW-M7)
- **CI coverage floor** raised from 70% to 75%. (NEW-M11)
- **Proptest invariants** replaced `prop_assert!(true)` and a narrow
  charset with real assertions on severity ordering, decoded
  idempotence, XFF leftmost-after-peel, and full-byte-space totality.
  (I-7, NEW-M2, NEW-M3)

### Fixed - robustness

- **`host.rs::drain_request_body`** infinite-loop on
  `(size=0, eof=false)` - added a zero-progress guard. (NEW-H4)
- **`host.rs::read_buf`** returning 16 MiB of zeros when
  `needed > MAX_ALLOC` - refuses the doomed second call, logs a host
  warning, returns empty. (NEW-H5)
- **Peer IP parsing** handles bare IPv6 (`::1`), bracketed forms
  (`[::1]`, `[::1]:8080`), bare IPv4 with and without port, and
  garbage. Pre-fix `rsplit_once(':')` collapsed every distinct IPv6
  peer to `::` (unspecified). (NEW-I5)
- **`signatures_inspect.rs` fuzz harness** caches
  `SignatureDetector::new()` across iterations (was 13× slower than
  sibling targets). (NEW-M4)

### Fixed - CI

- **`fuzz-smoke`** explicit `cargo +nightly fuzz` + job-level
  `RUSTUP_TOOLCHAIN: nightly`; `rust-toolchain.toml`'s stable pin no
  longer wins. (C-3)
- **`supply-chain`** bumped to `cargo-deny-action@v2`, which handles
  CVSS 4.0 entries in the upstream advisory DB.
- **`build.rs`** aligns wasm target triple to `wasm32-wasip1` and
  drops the dead `_WASI_EMULATED_PROCESS_CLOCKS` flag pair. (NEW-M12,
  NEW-M13)

### Fixed - release pipeline

- **`release.yml`** now requires:
  - `environment: release` gate (must have a configured required
    reviewer);
  - `concurrency` key (no two parallel publishes on the same tag);
  - SHA-pinned `sigstore/cosign-installer` and
    `softprops/action-gh-release` (NEW-I6);
  - `cosign verify-blob` immediately after signing - fail-closed if
    the asset can't be verified against its own certificate identity
    (NEW-H6);
  - `cargo publish --dry-run` before the real publish so a re-pushed
    tag doesn't leave a half-released state (NEW-I7).

---

## How to cut a release

1. Update `## [Unreleased]` in this file with a summary of changes under the
   sections of `Added`, `Changed`, `Fixed`, `Removed`.
2. Bump the shared workspace version, core path-version pin, lockfiles, Helm
   chart, and versioned installation examples.
3. From a clean working tree, run the same local gates as CI:
   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace --all-targets
   cargo test --workspace --doc
   cargo deny check
   ```
4. Land the release commit on `main` and wait for every workflow triggered by
   that exact commit to succeed before tagging it.
5. Create and push an annotated `vX.Y.Z` tag on the verified `main` commit.
   The tag triggers `.github/workflows/release.yml`, which builds the release
   WASM and relay binaries, publishes signed GHCR images and the OCI Helm chart,
   generates SPDX SBOMs, checksums and keyless Cosign signatures, creates the
   GitHub Release, and verifies every published asset before uploading the
   signed release manifest.
6. Wait for the release workflow to succeed, then follow
   [`docs/release-verification.md`](docs/release-verification.md) against the
   published tag.
