# Robustness & Detection Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every code change is TDD: failing test first, watch it fail, minimal code, watch it pass, commit.

**Goal:** Make purple-wolf measurably more robust and secure — close documented detection gaps, remove a latent CPU-DoS, make fail-open observable, and harden the relay — without regressing the benchmark moat (+0.1–0.2 ms p99, ~8k RPS at 200m CPU, flat 80–96 MiB).

**Architecture:** Changes are sequenced so the request hot path is only ever made *better under attack* (O(1) eviction) or pays cost solely on rare/attacker-shaped inputs (over-cap bodies, double-encoding, UA suffix). Detection lift rides aho-corasick's O(input) regardless-of-pattern-count economics. Observability and relay hardening live entirely off the WAF hot path. Each task is an independent, green, committed unit.

**Tech Stack:** Rust (workspace, MSRV 1.88, stable), `wasm32-wasip1` guest, libinjection (vendored C via FFI), `aho-corasick`, `percent-encoding`, tokio/reqwest (relay), `cargo-fuzz` (libfuzzer), criterion.

**Non-negotiable invariants preserved:** severity-over-order blocking, raw-bytes end-to-end, `deny_unknown_fields`, XFF `trusted_hops` default 0, fail-open default, single-line scrubbed JSON audit shape (additive fields only, `skip_serializing_if`).

---

## Hot-path cost budget (the gate every change passes)

| Change | Per-request cost | When paid |
|---|---|---|
| O(1) LRU eviction | strictly cheaper than today | only the eviction path, now constant not O(n) |
| decode-to-fixpoint | 0 on benign | only fields still containing `%` after pass 1 |
| signature pack expansion | ~0 (aho-corasick is O(input)) | always, but automaton size is irrelevant to throughput |
| null-byte / CRLF structural | one `memchr` over path+query | only when `structural` group enabled (default off) |
| UA SQLi suffix probe | ≤2 extra `is_sqli` calls on the UA value | every request with a User-Agent — the only measurable cost; `bench.yml` gate adjudicates |
| over-cap body prefix | one detector pass over already-buffered bytes | only over-cap requests (rare) |
| metering / audit fields | a few integer ops + bytes only when non-default | always, negligible |

---

## File structure

**Modified (core):**
- `crates/purple-wolf-core/src/detectors/reputation.rs` — replace O(n) eviction with O(1) intrusive-list LRU
- `crates/purple-wolf-core/src/request.rs` — decode-to-fixpoint; `body_truncated` field + setter; `user_agent()` accessor
- `crates/purple-wolf-core/src/detectors/signatures.rs` — expanded `SIGNATURES` table
- `crates/purple-wolf-core/src/detectors/structural.rs` — null-byte + CRLF checks
- `crates/purple-wolf-core/src/detectors/injection.rs` — UA suffix SQLi probe
- `crates/purple-wolf-core/src/audit.rs` — `body_truncated`, `config_fallback` fields (additive, skip-if-false)
- `crates/purple-wolf-core/benches/pipeline.rs` — reputation-under-rotation bench

**Modified (traefik):**
- `crates/purple-wolf-traefik/src/entry.rs` — inspect over-cap prefix; thread `body_truncated` + `config_fallback`; soft-failure/fail-open counters
- `crates/purple-wolf-traefik/src/host.rs` — counter state + health line emit
- `crates/purple-wolf-traefik/Cargo.toml` — `[[bin]] purple-wolf-validate`; lint config
- `crates/purple-wolf-traefik/src/bin/validate.rs` — **create**: native config validator

**Modified (relay):**
- `crates/purple-wolf-relay/src/config.rs` — admin auth config; disk-DLQ config
- `crates/purple-wolf-relay/src/admin.rs` (or wherever admin server lives) — optional bearer auth
- `crates/purple-wolf-relay/src/subscribers/dlq.rs` — optional append-only JSONL persistence
- `crates/purple-wolf-relay/src/enrich*.rs` — SSRF invariant test (operator-set URLs only)

**Created (fuzz):**
- `fuzz/fuzz_targets/client_ip.rs`, `fuzz/fuzz_targets/relay_parser.rs` + `fuzz/Cargo.toml` wiring

**Lint policy (Tier 0.1):**
- `crates/purple-wolf-core/src/lib.rs` + `crates/purple-wolf-traefik/src/lib.rs` — crate-level `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]` with audited `#[allow]` at the few legitimate sites (startup `expect`, test modules).

**Docs:**
- `Cargo.toml:40-41`, `THREAT_MODEL.md` (§4.3, §7.1, panic/trap reality), `docs/configuration.md`, `docs/benchmark.md` robustness rows, `CHANGELOG.md`
- `tests/corpus/clean/` — widened benign corpus

---

## Execution order & rationale

1. **Tier 1.4 — O(1) LRU** (vulnerability-shaped, self-contained, pure core)
2. **Tier 1.5 — decode-to-fixpoint** (closes cheapest evasion)
3. **Tier 2.9/2.11 — signatures + structural** (detection lift, near-zero cost)
4. **Tier 2.10 — UA suffix probe** (closes a documented gap; only measurable-cost item)
5. **Tier 1.6 — over-cap body prefix** (closes §4.2 lever; adds `body_truncated`)
6. **Tier 0 — panic/trap docs+lints, metering, `config_fallback`, validate binary** (make claims true + observable)
7. **Tier 1.7 — fuzz targets** (XFF + relay parser)
8. **Tier 3 — relay auth + disk DLQ + SSRF invariant**
9. **Tier 2.8 + docs — benign corpus + doc refresh + CHANGELOG + benchmark rerun rows**

Each tier below is implemented strictly test-first. The detailed RED/GREEN/COMMIT steps are executed inline; this document records the design, the exact code shapes, and the test obligations so the work is reproducible and reviewable.

---

## Tier 1.4 — O(1) LRU eviction

**Defect:** `reputation.rs` evicts via `buckets.iter().min_by_key(last_seen_seq)` — O(n). Once an attacker fills the map to `max_tracked_ips` (50k) by rotating source IPs, *every* subsequent new-IP request triggers a full 50k-entry scan. The memory-DoS mitigation became a CPU-DoS lever, exhausting the 200m CPU budget far below the benign RPS ceiling.

**Design:** Intrusive doubly-linked-list LRU over a slab `Vec<Node>`, sentinel `usize::MAX` for none, `HashMap<IpAddr, usize>` index, free-list for slot reuse. `head` = MRU, `tail` = LRU. Access → `move_to_front` (O(1)). Insert-when-full → evict `tail` (O(1)), reuse slot. No new deps, no DashMap/futures — preserves the no-async stance.

**Test obligations (all in `reputation.rs` tests):**
- Preserve: `flags_denied_ip`, `rate_limits_burst_from_one_ip`.
- Rewrite to new accessor API (`tracked_len()`, `tracked_contains(ip)`): `bounded_map_evicts_lru_when_full`, `evicts_least_recently_used_not_most_recently_used`.
- NEW (write first, watch fail): `eviction_order_is_strict_lru_under_churn` — fill cap, then insert `5*cap` fresh IPs; assert exactly the oldest are gone and the most-recent `cap` survive; assert `tracked_len() == cap` throughout.
- NEW: `refill_math_survives_slot_reuse` — an IP evicted then re-seen starts with a fresh full bucket (no stale token state from the reused slot).
- Bench (criterion): `reputation_rotation` — sustained new-IP inserts at full cap; documents constant-time eviction.

---

## Tier 1.5 — Percent-decode to fixpoint (bounded)

**Defect:** `decode()` runs exactly one pass; `%2527%2520OR` (double-encoded `' OR`) reaches detectors as `%27 OR` and never matches.

**Design:**
```rust
/// Max percent-decode passes. WAFs must decode-to-fixpoint to defeat
/// multi-encoding evasion, but an unbounded loop is a DoS; 3 passes
/// covers triple-encoding (observed ceiling for real evasion kits)
/// while staying O(1). Inspection-only: we never forward the decoded
/// form, so over-decoding raises inspection aggressiveness, not the
/// bytes sent upstream.
const MAX_DECODE_PASSES: usize = 3;

fn decode(s: &str) -> String {
    let mut cur = percent_decode_str(s).decode_utf8_lossy().into_owned();
    for _ in 1..MAX_DECODE_PASSES {
        if !cur.contains('%') { break; }            // fixpoint: nothing left to decode
        let next = percent_decode_str(&cur).decode_utf8_lossy().into_owned();
        if next == cur { break; }                   // fixpoint: stable
        cur = next;
    }
    cur
}
```

**Test obligations (`request.rs` + `injection.rs`):**
- NEW (fail first): `double_encoded_sqli_in_query_is_decoded` — `id=%252527%252520OR%252520%2525271%252527%25253D%2525271` (double-encoded `' OR '1'='1`) → `query_params` value contains `' OR '1'='1`.
- NEW: `decode_stops_at_fixpoint_and_is_bounded` — a value with no `%` is returned unchanged in one pass; a value that is literally `%` (no hex) is stable and not looped pathologically.
- NEW (`injection.rs`): `flags_double_encoded_sqli_in_query` — double-encoded cookie/query SQLi now fires `sqli`.
- Preserve: `decodes_query_params` (single-decode unchanged).
- Guard FPR: `benign_percent_literal_not_mangled` — a benign value like `discount=50%25off` decodes to `50%off` and does NOT produce an injection verdict.

---

## Tier 2.9 / 2.11 — Signature pack + structural checks

**Signature additions** (`SIGNATURES`, collision-aware, precision-first):
```rust
(";wget", "rce_cmd", Severity::Critical),
(";curl", "rce_cmd", Severity::Critical),
(";bash", "rce_cmd", Severity::Critical),
(";nc ",  "rce_cmd", Severity::Critical),   // trailing space avoids `;ncount`
("|bash", "rce_cmd", Severity::Critical),
("|sh ",  "rce_cmd", Severity::Critical),
("${jndi:", "jndi_lookup", Severity::Critical),  // Log4Shell
("php://",  "php_wrapper", Severity::High),
("phar://", "php_wrapper", Severity::High),
("expect://", "php_wrapper", Severity::Critical),
("/etc/shadow", "lfi", Severity::Critical),
("/proc/self/environ", "lfi", Severity::Critical),
("/web-inf/", "lfi", Severity::High),       // case-insensitive matcher → matches /WEB-INF/
("xp_cmdshell", "rce_sql", Severity::Critical),
```
Deliberately **not** bare `;id` / `;ls` (collide with `sessionid=…;id=…` cookies, `details`).

**Structural additions** (`structural.rs`, scoped to decoded path + decoded query values):
- `null_byte` (Medium): any inspected URL field contains `\0` (post-decode `%00`) — LFI truncation primitive.
- `crlf_injection` (Medium): path or a query value contains `\r` or `\n` (post-decode `%0d%0a`) — header/response-splitting adjacency.

**Test obligations:**
- For EACH new signature: an attack test that fires the expected `rule`, plus a representative benign test in the same area that does NOT fire (e.g. `php_wrapper_does_not_fp_on_index_php_url`, `rce_cmd_does_not_fp_on_semicolon_cookie`).
- `structural.rs`: `flags_null_byte_in_path`, `flags_crlf_in_query_value`, `normal_request_is_clean` still green, and a benign multiline-free request produces nothing.
- Engine-level: extend `crs_replay.rs` expectations only if it tightens a known class without moving FPR.

---

## Tier 2.10 — User-Agent SQLi suffix probe

**Gap:** libinjection fingerprints `Mozilla/5.0 1 OR 1=1` as a UA string and misses the SQLi.

**Design:** Add `Request::user_agent() -> Option<&str>`. In `InjectionDetector`, after the main field loop, if a UA exists, derive up to two suffix candidates — substring after the first ASCII space, and substring after the last `)` — and run `ffi::is_sqli` on each distinct candidate that differs from the whole value. First hit emits one `sqli` verdict (dedup so a UA already caught in the main loop isn't double-counted). Empirically verify libinjection flags the isolated suffix during GREEN; if it doesn't, fall back to a `user-agent`-scoped signature instead (documented decision).

**Test obligations (`injection.rs`):**
- NEW (fail first): `flags_mozilla_prefixed_sqli_in_user_agent` — `User-Agent: Mozilla/5.0 1 OR 1=1` → `sqli` verdict.
- NEW: `benign_user_agent_does_not_false_positive` — `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36` → no verdict.
- NEW: `user_agent_sqli_not_double_counted` — a UA that fires in the main loop yields exactly one `sqli` verdict.

---

## Tier 1.6 — Inspect over-cap body prefix

**Lever (§4.2):** over-cap + `overCap: pass` → body inspection skipped entirely, yet the first `maxInspectBytes` were already buffered. Prepending 1 MiB of padding defeats body detection for free.

**Design:**
- `request.rs`: add `body_truncated: bool` field, defaulted false in `build`, set via `with_truncated_body(self, bool) -> Self` (additive, no call-site churn).
- `entry.rs`: when over-cap and `overCap: pass`, build the request with the buffered prefix and `body_inspected = true` (we inspect what we have) and `.with_truncated_body(true)`. Attacker must now place the payload *past* the cap, not merely inflate the body.
- `audit.rs`: add `#[serde(skip_serializing_if = "is_false")] body_truncated: bool`, sourced from `req.body_truncated`.

**Test obligations:**
- `request.rs`: `body_truncated_defaults_false`, `with_truncated_body_sets_flag`, `inspectable_fields_includes_prefix_when_truncated_but_inspected`.
- `audit.rs`: `audit_marks_body_truncated_when_set`, `audit_omits_body_truncated_when_false` (v0.2 shape preserved).
- traefik `entry.rs` native test (if reachable) or core-level: a payload inside the prefix of an over-cap body is detected.

---

## Tier 0 — Make claims true + observable

**0.1 Panic/trap reality.** Unwinding is unavailable on `wasm32-wasip1` (`panic="abort"`), so `catch_unwind` cannot catch detector panics in the shipped guest. Fix:
- Add deny-level clippy lints (above) to structurally exclude panics; `#[allow]` the audited startup `expect` in `signatures.rs` and test modules.
- Rewrite `Cargo.toml:40-41` and `THREAT_MODEL.md:232-234` to state the reality: panics are structurally excluded; a panic-inducing input traps the guest and Traefik applies its plugin-failure directive (test-documented), so `failMode` is honored for *detector errors/over-cap*, not hard panics.
- Add a `#[ignore]`d Docker integration test (or a documented manual probe) that builds a guest with an intentional panic behind a test cfg and records Traefik's observed response code.

**0.2 Metering.** Thread-local counters in `host.rs` (libinjection `-1`, over-cap, would-be soft failures); emit a `purple_wolf_health` JSON line periodically/on-change that the relay already-existing parser can turn into gauges. Native unit tests on the counter logic.

**0.3 Loud config fallback + validate binary.**
- `audit.rs`: `#[serde(skip_serializing_if = "is_false")] config_fallback: bool`; `entry.rs` sets it true while on the all-monitor fallback config so dashboards/relay see it continuously (not just one startup log line).
- `crates/purple-wolf-traefik/src/bin/validate.rs`: native binary parsing a middleware config file/stdin with the **same** `adapter::parse`, exit non-zero + human-readable errors on failure. Parity with relay `--validate-only`. Tests via `assert_cmd` or direct function calls.

---

## Tier 1.7 — Fuzz targets

- `fuzz/fuzz_targets/client_ip.rs`: arbitrary header list + `trusted_hops` → `request::client_ip` never panics.
- `fuzz/fuzz_targets/relay_parser.rs`: arbitrary bytes → relay log-line parser (balanced-brace JSON extraction) never panics. A panic here is a remote relay-DoS via crafted HTTP.
- Wire both into the `fuzz-smoke` CI job (short run on the committed corpus).

---

## Tier 3 — Relay hardening

- **Admin auth:** optional `admin.auth_token` (env/file); when set, `/metrics /healthz /readyz /version` require `Authorization: Bearer <token>`; when unset, log a one-time warning (preserve default-on behavior). Tests: 401 without/with bad token, 200 with good token, open when unset.
- **Disk-backed DLQ:** opt-in append-only JSONL (`dlq.path`); on enqueue append, on restart reload, bounded by size; pairs with planned v0.4 replay. Tests: round-trip persistence, bounded truncation, disabled-by-default.
- **SSRF invariant:** test proving the HTTP enricher's fetched URL is composed only from operator-set config, never from attacker-influenced audit fields; encode as a regression test.

---

## Tier 2.8 + docs

- Widen `tests/corpus/clean/` from 53 to a few thousand realistic benign shapes (REST/GraphQL/form/JSON-API, markdown, base64 blobs, semicolon cookies, jQuery-era query strings) — generated, committed; becomes the FPR regression gate every new signature passes (0% FPR must hold).
- Refresh `THREAT_MODEL.md` (panic/trap reality, metering, decode-to-fixpoint, over-cap prefix, relay auth), `docs/configuration.md` (new signatures, validate binary, relay auth/DLQ), `docs/benchmark.md` (retire `;wget` and Mozilla-UA "missed" robustness rows after a rerun), `CHANGELOG.md`.
- Add SLSA provenance attestation to the release workflow.

---

## Definition of done

- `cargo test --workspace --all-targets` green; `cargo clippy --workspace --all-targets -- -D warnings` clean under the new deny-lints.
- `cargo build -p purple-wolf-traefik --target wasm32-wasip1 --release` succeeds.
- Every new signature/check has a firing test AND a benign non-firing test; benign corpus FPR stays 0%.
- `bench.yml` criterion gate (>10% regression fails) passes — the UA probe is the only measurable cost and must stay under budget.
- Docs no longer assert anything false about panic handling; new behavior documented.
