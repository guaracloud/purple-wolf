# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security & robustness hardening

- **O(1) reputation-limiter eviction.** The bounded per-IP token-bucket map
  previously evicted via an O(n) scan; once an attacker filled it to the cap
  by rotating source IPs, every new-IP request scanned all entries — a
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
  enforcement is silently off — not just one startup log line.
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

### Added — v0.3 audit labels + webhook relay

- **`Config.labels: BTreeMap<String, String>`** on every Middleware. Free-form
  `key=value` metadata that the WAF echoes verbatim into every audit-log line
  for that Middleware. Keys match `^[a-z][a-z0-9_.-]{0,62}$`, ≤32 keys,
  ≤4 KiB total (BTreeMap → deterministic alphabetical JSON). The
  reserved-prefix `purple_wolf.*` is dropped at the adapter with a
  one-warning-per-key log so a tenant who copied an example can't shadow
  WAF-set fields. Value scrubbing strips ASCII control chars at audit-emit
  time (same log-injection guard as `blocked_detail`). See
  [`docs/configuration.md` § Labels](docs/configuration.md#labels).
- **`purple-wolf-relay` (new crate, `0.3.0`)** — standalone, vendor-neutral
  webhook fan-out for purple-wolf audit events. Tails Traefik's stdout (or
  stdin), parses the audit JSON, optionally enriches labels, evaluates
  per-subscriber filters (label subset / severity floor / glob rule
  pattern), and delivers HMAC-SHA256-signed POSTs with exponential backoff
  retries + bounded DLQ. Per-subscriber bounded mpsc isolates slow
  subscribers from fast ones; on-disk bookmark resume across restarts.
  Distroless multi-arch Docker image at
  `ghcr.io/guaracloud/purple-wolf-relay`. Prometheus `/metrics`,
  `/healthz`, `/readyz`, `/version`.
- **`docs/webhook-protocol.md`** — stable `purple-wolf.audit/v1` envelope
  spec (HMAC scheme, idempotency, retry semantics, versioning policy,
  reference subscriber implementations in Python / Go / TypeScript).
- **`relay-integration` CI job** runs a full-stack docker-compose
  (Traefik + WAF + relay + mock subscriber) and asserts a SQLi attack
  produces a verified HMAC-signed envelope at the subscriber with
  the operator's labels intact.

### Added — detection scope

- **Inspect allow-listed request headers** (Cookie, Referer, Host,
  Authorization, User-Agent, any `X-*` custom header) for both raw and
  percent-decoded forms. The pre-fix engine silently ignored every
  header except User-Agent — Cookie/Referer SQLi returned 200 with no
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

### Changed — invariants

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
  `false` — a typo trap). (NEW-M6)
- **`perSecond: 0` and `maxInspectBytes: 0`** are now parse errors
  instead of silent coercions. (NEW-M7)
- **CI coverage floor** raised from 70% to 75%. (NEW-M11)
- **Proptest invariants** replaced `prop_assert!(true)` and a narrow
  charset with real assertions on severity ordering, decoded
  idempotence, XFF leftmost-after-peel, and full-byte-space totality.
  (I-7, NEW-M2, NEW-M3)

### Fixed — robustness

- **`host.rs::drain_request_body`** infinite-loop on
  `(size=0, eof=false)` — added a zero-progress guard. (NEW-H4)
- **`host.rs::read_buf`** returning 16 MiB of zeros when
  `needed > MAX_ALLOC` — refuses the doomed second call, logs a host
  warning, returns empty. (NEW-H5)
- **Peer IP parsing** handles bare IPv6 (`::1`), bracketed forms
  (`[::1]`, `[::1]:8080`), bare IPv4 with and without port, and
  garbage. Pre-fix `rsplit_once(':')` collapsed every distinct IPv6
  peer to `::` (unspecified). (NEW-I5)
- **`signatures_inspect.rs` fuzz harness** caches
  `SignatureDetector::new()` across iterations (was 13× slower than
  sibling targets). (NEW-M4)

### Fixed — CI

- **`fuzz-smoke`** explicit `cargo +nightly fuzz` + job-level
  `RUSTUP_TOOLCHAIN: nightly`; `rust-toolchain.toml`'s stable pin no
  longer wins. (C-3)
- **`supply-chain`** bumped to `cargo-deny-action@v2`, which handles
  CVSS 4.0 entries in the upstream advisory DB.
- **`build.rs`** aligns wasm target triple to `wasm32-wasip1` and
  drops the dead `_WASI_EMULATED_PROCESS_CLOCKS` flag pair. (NEW-M12,
  NEW-M13)

### Fixed — release pipeline

- **`release.yml`** now requires:
  - `environment: release` gate (must have a configured required
    reviewer);
  - `concurrency` key (no two parallel publishes on the same tag);
  - SHA-pinned `sigstore/cosign-installer` and
    `softprops/action-gh-release` (NEW-I6);
  - `cosign verify-blob` immediately after signing — fail-closed if
    the asset can't be verified against its own certificate identity
    (NEW-H6);
  - `cargo publish --dry-run` before the real publish so a re-pushed
    tag doesn't leave a half-released state (NEW-I7).

---

## How to cut a release

1. Update `## [Unreleased]` in this file with a summary of changes under the
   sections of `Added`, `Changed`, `Fixed`, `Removed`.
2. Decide the next version (semver — `cargo-release` defaults to patch).
3. From a clean working tree on a release branch:
   ```bash
   git checkout -b release/v0.2.0
   cargo release 0.2.0 --execute
   ```
   cargo-release will:
   - bump `[workspace.package].version` to `0.2.0` (shared-version)
   - commit `chore(release): 0.2.0` (signed)
   - tag `v0.2.0` (signed)
   - push branch and tag to `origin`
4. The push of the `v*` tag triggers `.github/workflows/release.yml`, which:
   - builds the release `.wasm` against `wasm32-wasip1`
   - computes a SHA256 and cosign-signs the blob (keyless OIDC)
   - re-verifies the signature against its own certificate identity
     (fail-closed)
   - creates a GitHub Release with the `.wasm`, `.sha256`, `.sig`, `.pem`
     attached
   - dry-runs and then publishes `purple-wolf-core` to crates.io
     (requires `CARGO_REGISTRY_TOKEN` secret + the `release` environment
     gate)
5. Open a PR back to `main` from the release branch, merge after CI passes.
