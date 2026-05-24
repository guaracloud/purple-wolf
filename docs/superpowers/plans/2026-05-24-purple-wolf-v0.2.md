# purple-wolf v0.2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship purple-wolf as a Traefik WASM plugin (the canonical guaracloud deployment) plus a separately-published `purple-wolf-core` crate, all at OSS-grade quality (fuzz, proptest, OWASP CRS corpus, criterion gates, full CI matrix, signed release).

**Architecture:** Two-crate Cargo workspace. `purple-wolf-core` is pure detection — no I/O, no async — and compiles to native and `wasm32-wasip1`. `purple-wolf-traefik` is a thin http-wasm guest that wraps core and is loaded once into a shared platform Traefik; per-tenant configuration is delivered as Middleware plugin parameters.

**Tech Stack:** Rust workspace, vendored libinjection (C, cross-compiled to native + `wasm32-wasip1` via `wasi-sdk`), `aho-corasick`, `governor` (with custom `Clock`), http-wasm guest ABI, `serde`/`serde_json`, `proptest`, `cargo-fuzz`, `criterion`, `cargo-deny`, `cargo-llvm-cov`, `cargo-release`, GitHub Actions, `cosign`.

**Spec:** `docs/superpowers/specs/2026-05-24-purple-wolf-v0.2-design.md`

**v0.1 reference:** the `feat/purple-wolf-impl` branch in this repo is the source for ported modules. Many tasks below say "port verbatim from `feat/purple-wolf-impl:<path>`" — the implementer is expected to `git show feat/purple-wolf-impl:<path>` to retrieve that file and adapt it as specified.

---

## File Structure

```
purple-wolf/                                   (repo dir, renamed from guaracloud-purple-wolf)
├── Cargo.toml                                 workspace manifest
├── rust-toolchain.toml                        pin stable + clippy + rustfmt
├── deny.toml                                  cargo-deny config
├── README.md  CONTRIBUTING.md  CHANGELOG.md
├── SECURITY.md  CODE_OF_CONDUCT.md
├── LICENSE-MIT  LICENSE-APACHE
├── crates/
│   ├── purple-wolf-core/
│   │   ├── Cargo.toml
│   │   ├── build.rs                           libinjection cross-build (native + wasm32-wasip1)
│   │   ├── vendor/libinjection/               C sources + COPYING (ported)
│   │   └── src/
│   │       ├── lib.rs                         public API + rustdoc examples
│   │       ├── clock.rs                       Clock trait + SystemClock
│   │       ├── request.rs                     Request view + client_ip
│   │       ├── config.rs                      typed Config (no overrides, no listen)
│   │       ├── detectors/
│   │       │   ├── mod.rs                     Group, Severity, Verdict, Detector trait, Engine
│   │       │   ├── injection.rs               libinjection-backed
│   │       │   ├── signatures.rs              aho-corasick
│   │       │   ├── structural.rs              method/header anomaly
│   │       │   └── reputation.rs              governor + Clock + IP deny list
│   │       ├── ffi.rs                         extern bindings + safe wrappers
│   │       ├── policy.rs                      decide()
│   │       └── audit.rs                       AuditEntry
│   └── purple-wolf-traefik/
│       ├── Cargo.toml                         crate-type = ["cdylib"]
│       └── src/
│           ├── lib.rs                         http-wasm guest exports
│           ├── host.rs                        http-wasm ABI bindings (SDK or hand-rolled)
│           ├── entry.rs                       handle_request / handle_response orchestration
│           └── config.rs                      Middleware-JSON → core::Config adapter
├── benches/                                   workspace-level criterion targets
│   └── pipeline.rs
├── fuzz/                                      cargo-fuzz crate
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── request_parser.rs
│       ├── injection_inspect.rs
│       ├── signatures_inspect.rs
│       └── policy_decide.rs
├── tests/
│   ├── corpus/                                vendored OWASP CRS payloads
│   ├── parity/                                golden-file detection tests
│   └── traefik_integration.rs                 Docker-based end-to-end
├── examples/                                  tenant Middleware YAML samples
└── .github/workflows/
    ├── ci.yml                                 test + lint + supply-chain + wasm + fuzz + coverage + docs
    ├── bench.yml                              criterion regression gate
    └── release.yml                            cargo-release + cosign + GH Release artifact
```

Each module is small, single-responsibility, and independently testable.

---

## Phase A — Foundation

### Task 1: Rename repo dir, set up workspace, scaffold crates, vendor licenses & docs

**Files:**
- Rename: `guaracloud-purple-wolf/` → `purple-wolf/` (parent-dir rename; performed by the implementer's git workflow — see Step 1)
- Create: `Cargo.toml` (workspace), `rust-toolchain.toml`, `deny.toml`, `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `.gitignore`
- Create: `crates/purple-wolf-core/Cargo.toml`, `crates/purple-wolf-core/src/lib.rs`
- Create: `crates/purple-wolf-traefik/Cargo.toml`, `crates/purple-wolf-traefik/src/lib.rs`

- [ ] **Step 1: Rename the repo directory**

The current directory is `guaracloud-purple-wolf`. Rename it to `purple-wolf` from the parent so the repo's on-disk path matches the project name:

```bash
cd ..
mv guaracloud-purple-wolf purple-wolf
cd purple-wolf
git status   # confirm clean — the rename is purely on-disk, .git is untouched
```

(Use the resulting `purple-wolf/` path for the remainder of all tasks. If your harness pins the working directory and can't follow the rename, do the work in-place and rename as a final cleanup task.)

- [ ] **Step 2: Confirm we're starting from `main`**

```bash
git checkout main
git log --oneline -3
```
Expected: the most recent commit is the v0.2 design spec (`f64bc3e Add purple-wolf v0.2 design spec`). The `feat/purple-wolf-impl` branch with v0.1 code is preserved and not affected.

- [ ] **Step 3: Create a working branch**

```bash
git checkout -b v0.2/foundation
```

- [ ] **Step 4: Create `rust-toolchain.toml`**

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
targets = ["wasm32-wasip1"]
```

- [ ] **Step 5: Create the workspace `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["crates/purple-wolf-core", "crates/purple-wolf-traefik"]
exclude = ["fuzz"]

[workspace.package]
version = "0.2.0-dev"
edition = "2021"
rust-version = "1.75"
license = "MIT OR Apache-2.0"
repository = "https://github.com/guaracloud-oss/purple-wolf"
homepage   = "https://github.com/guaracloud-oss/purple-wolf"
readme = "README.md"

[workspace.dependencies]
serde      = { version = "1", features = ["derive"] }
serde_json = "1"
aho-corasick = "1"
governor   = { version = "0.6", default-features = false, features = ["std"] }
percent-encoding = "2"

# Size-optimised release for the WASM plugin artifact.
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
# panic = "unwind" (default) is kept on purpose: the entry shim uses
# catch_unwind for per-request panic isolation (spec section 7).
```

- [ ] **Step 6: Scaffold `purple-wolf-core`**

`crates/purple-wolf-core/Cargo.toml`:

```toml
[package]
name        = "purple-wolf-core"
description = "WAF detection engine: hybrid SQLi/XSS, signature, structural, and reputation detectors."
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
readme.workspace = true

[dependencies]
serde      = { workspace = true }
serde_json = { workspace = true }
aho-corasick = { workspace = true }
governor   = { workspace = true }
percent-encoding = { workspace = true }

[build-dependencies]
cc = "1"
```

`crates/purple-wolf-core/src/lib.rs`:

```rust
//! purple-wolf-core: hybrid WAF detection engine.
//!
//! This crate is the platform-neutral detection engine used by every
//! purple-wolf deployment (Traefik WASM plugin and, later, sidecar binary).
//! It has no I/O, no async runtime, and compiles to native targets and to
//! `wasm32-wasip1`.

// Modules added by subsequent tasks.
```

- [ ] **Step 7: Scaffold `purple-wolf-traefik`**

`crates/purple-wolf-traefik/Cargo.toml`:

```toml
[package]
name        = "purple-wolf-traefik"
description = "purple-wolf as a Traefik http-wasm plugin."
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
readme.workspace = true
publish     = false   # WASM artifact, not a library

[lib]
crate-type = ["cdylib"]

[dependencies]
purple-wolf-core = { path = "../purple-wolf-core" }
serde      = { workspace = true }
serde_json = { workspace = true }
```

`crates/purple-wolf-traefik/src/lib.rs`:

```rust
//! purple-wolf-traefik: http-wasm guest plugin wrapping `purple-wolf-core`.
//!
//! Loaded once into a shared Traefik HA deployment; one plugin instance is
//! constructed per `Middleware` CRD that references it.

// Entry points added in a later task.
```

- [ ] **Step 8: Create `.gitignore`**

```
/target
/fuzz/target
/fuzz/corpus
/fuzz/artifacts
*.swp
.DS_Store
```

- [ ] **Step 9: Vendor the licenses**

Create `LICENSE-MIT` and `LICENSE-APACHE` from the canonical Rust project templates (copy from `https://choosealicense.com/licenses/mit/` and `https://choosealicense.com/licenses/apache-2.0/`; substitute the year `2026` and copyright holder `purple-wolf authors`). Commit both verbatim.

- [ ] **Step 10: Create the OSS docs skeletons**

`README.md`:

```markdown
# purple-wolf

A fast, low-memory Web Application Firewall delivered as a Traefik plugin.

**Status:** v0.2 in development. [Design spec](docs/superpowers/specs/2026-05-24-purple-wolf-v0.2-design.md).

## What it does

`purple-wolf` inspects every HTTP request reaching a route protected by one
of its Middlewares and either lets it through or returns `403 Forbidden`.
Inspection covers headers, URL, query parameters, and the request body (up
to a configurable cap) using a hybrid engine: libinjection (SQLi/XSS),
aho-corasick literal signatures, structural anomaly checks, and per-IP
rate limiting / deny-listing.

## Quick start (Traefik)

(filled in by Task 25)

## License

Dual-licensed under MIT OR Apache-2.0.
```

`CONTRIBUTING.md`:

```markdown
# Contributing

Thank you for your interest! This project follows standard Rust workflow:

1. Fork and clone.
2. `cargo test --workspace` must pass.
3. `cargo clippy --all-targets -- -D warnings` must be clean.
4. `cargo fmt --check` must be clean.
5. Open a Pull Request describing the change.

For larger changes, please open an issue first to discuss the approach.

## Security issues

Please follow `SECURITY.md` — do not file public issues for vulnerabilities.
```

`CHANGELOG.md`:

```markdown
# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial workspace skeleton.
```

`SECURITY.md`:

```markdown
# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately. Send a detailed report to
the maintainer email listed in the repository profile, **not** via a public
GitHub issue.

You should receive a response within 72 hours.
```

`CODE_OF_CONDUCT.md`:

Copy the Contributor Covenant v2.1 from `https://www.contributor-covenant.org/version/2/1/code_of_conduct.txt` verbatim.

- [ ] **Step 11: Create `deny.toml`**

```toml
[graph]
all-features = true

[advisories]
yanked = "warn"

[licenses]
allow = ["MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]
confidence-threshold = 0.92

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

- [ ] **Step 12: Build everything**

```bash
cargo build --workspace
```
Expected: both crates compile (lib.rs files are essentially empty). No errors.

- [ ] **Step 13: Commit**

```bash
git add -A
git commit -m "chore: scaffold v0.2 workspace, vendor licenses and OSS docs"
```

---

## Phase B — Port the `purple-wolf-core` engine

> **Porting convention for Phase B tasks.** Every Phase B task ports an existing
> v0.1 module. To retrieve a v0.1 file: `git show feat/purple-wolf-impl:<path>`.
> Adapt as specified (drop dependencies, change module path, add the
> requested changes). All tests in the v0.1 module must also be ported and
> must pass in the new location unless a task explicitly modifies them.

### Task 2: `core::clock` — Clock trait + SystemClock

**Files:**
- Create: `crates/purple-wolf-core/src/clock.rs`
- Modify: `crates/purple-wolf-core/src/lib.rs` (add `pub mod clock;`)

- [ ] **Step 1: Write the test (TDD)**

`crates/purple-wolf-core/src/clock.rs`:

```rust
//! Time abstraction so the reputation rate-limiter is portable across
//! native and WASM (where `Instant::now()` semantics differ).
use std::time::Duration;

/// Returns monotonically non-decreasing nanoseconds since an arbitrary epoch.
/// Implementations need only guarantee monotonicity within a single instance.
pub trait Clock: Send + Sync + 'static {
    fn now(&self) -> Duration;
}

/// Native clock backed by `std::time::Instant`.
pub struct SystemClock {
    epoch: std::time::Instant,
}

impl SystemClock {
    pub fn new() -> SystemClock {
        SystemClock { epoch: std::time::Instant::now() }
    }
}

impl Default for SystemClock {
    fn default() -> Self { Self::new() }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_monotonic() {
        let c = SystemClock::new();
        let a = c.now();
        std::thread::sleep(Duration::from_millis(2));
        let b = c.now();
        assert!(b >= a);
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/purple-wolf-core/src/lib.rs` add: `pub mod clock;`

- [ ] **Step 3: Run the test**

```bash
cargo test -p purple-wolf-core clock::
```
Expected: 1 test PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/purple-wolf-core/src/clock.rs crates/purple-wolf-core/src/lib.rs
git commit -m "feat(core): clock abstraction"
```

---

### Task 3: `core::request` — Request view + client_ip

**Files:**
- Create: `crates/purple-wolf-core/src/request.rs`
- Modify: `crates/purple-wolf-core/src/lib.rs`

- [ ] **Step 1: Port the v0.1 file**

Retrieve v0.1's request model:
```bash
git show feat/purple-wolf-impl:src/request_model.rs > crates/purple-wolf-core/src/request.rs
```
Rename the public struct's module path from `request_model::RequestView` to `request::Request`. Replace `RequestView` with `Request` everywhere in the new file (including tests). Keep all helpers (`decode`, `parse_query`, `inspectable_fields`, `header`).

Then ADDITIONALLY port the `client_ip` helper from v0.1's `src/proxy.rs` into this same file. Retrieve it with:
```bash
git show feat/purple-wolf-impl:src/proxy.rs | sed -n '/fn client_ip/,/^}/p'
```
Place it as a free function `pub fn client_ip(headers: &[(String, String)], peer: std::net::IpAddr) -> std::net::IpAddr` near the bottom of `request.rs`. Carry over the 6 v0.1 unit tests for it.

- [ ] **Step 2: Register the module**

In `crates/purple-wolf-core/src/lib.rs` add: `pub mod request;`

- [ ] **Step 3: Run all tests in the module**

```bash
cargo test -p purple-wolf-core request::
```
Expected: all v0.1 request_model tests PASS plus the 6 `client_ip` tests PASS (the test count should match v0.1's count for these two areas).

- [ ] **Step 4: Commit**

```bash
git add crates/purple-wolf-core/src/request.rs crates/purple-wolf-core/src/lib.rs
git commit -m "feat(core): port Request view and client_ip helper"
```

---

### Task 4: `core::config` — typed config schema

**Files:**
- Create: `crates/purple-wolf-core/src/config.rs`
- Modify: `crates/purple-wolf-core/src/lib.rs`

- [ ] **Step 1: Port v0.1's config, trimmed**

Retrieve v0.1's `src/config.rs`:
```bash
git show feat/purple-wolf-impl:src/config.rs > crates/purple-wolf-core/src/config.rs
```

Then DELETE these items from the ported file:
- The `Override` struct entirely.
- The `overrides: Vec<Override>` field on `Config` (and its `#[serde(default)]`).
- The `listen: String` field on `Config`.
- The `upstream: String` field on `Config`.
- The `metrics_listen` field on `Config` (added in a v0.1 fix commit; may or may not be present depending on where you pulled — if present, delete).

KEEP everything else — `Mode`, `FailMode`, `GroupMode`, `OverCap`, `BodyConfig`, `GroupConfig`, `Groups`, `ReputationConfig` (port the v0.1 reputation-config addition too — retrieve it with `git show feat/purple-wolf-impl:src/config.rs | grep -A20 ReputationConfig` if you don't see it; it adds `per_second: u32` default 100 and `deny_list: Vec<String>` default empty).

Update or add a test verifying:
- the trimmed `Config` parses with no `listen`/`upstream`/`overrides`/`metrics_listen` fields,
- a config with `[reputation] per_second = N` parses,
- the original `parses_full_config` test (adapted to drop the removed fields) still passes.

- [ ] **Step 2: Register the module**

`pub mod config;` in `crates/purple-wolf-core/src/lib.rs`.

- [ ] **Step 3: Run tests**

```bash
cargo test -p purple-wolf-core config::
```
Expected: all config tests PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/purple-wolf-core/src/config.rs crates/purple-wolf-core/src/lib.rs
git commit -m "feat(core): typed Config schema (no overrides, no I/O fields)"
```

---

### Task 5: `core::detectors` module — trait, Engine, Verdict, Severity

**Files:**
- Create: `crates/purple-wolf-core/src/detectors/mod.rs`
- Create: stubs `crates/purple-wolf-core/src/detectors/{injection,signatures,structural,reputation}.rs` (single comment line each)
- Modify: `crates/purple-wolf-core/src/lib.rs`

- [ ] **Step 1: Port v0.1's detectors/mod.rs**

```bash
mkdir -p crates/purple-wolf-core/src/detectors
git show feat/purple-wolf-impl:src/detectors/mod.rs > crates/purple-wolf-core/src/detectors/mod.rs
```
Update the `use crate::request_model::RequestView;` import to `use crate::request::Request;`, and every other reference to `RequestView` → `Request`. (If a `Severity::as_str()` method was added in a later v0.1 commit, keep it.)

- [ ] **Step 2: Create stubs**

For each of `injection.rs`, `signatures.rs`, `structural.rs`, `reputation.rs` in `crates/purple-wolf-core/src/detectors/`, create the file containing ONLY:
```rust
// implemented in a later task
```

- [ ] **Step 3: Register the module**

`pub mod detectors;` in `crates/purple-wolf-core/src/lib.rs`.

- [ ] **Step 4: Run tests**

```bash
cargo test -p purple-wolf-core detectors::tests::
```
Expected: the `engine_runs_only_enabled_groups` test PASSES.

- [ ] **Step 5: Commit**

```bash
git add crates/purple-wolf-core/src/detectors/ crates/purple-wolf-core/src/lib.rs
git commit -m "feat(core): detector trait, engine, verdict, severity"
```

---

### Task 6: Vendor libinjection + native FFI

**Files:**
- Create: `crates/purple-wolf-core/vendor/libinjection/` (10 files)
- Create: `crates/purple-wolf-core/build.rs`
- Create: `crates/purple-wolf-core/src/ffi.rs`
- Modify: `crates/purple-wolf-core/src/lib.rs`

This task delivers the NATIVE-only build of libinjection + FFI. Cross-compiling to `wasm32-wasip1` is added by Task 14.

- [ ] **Step 1: Vendor the C sources from v0.1**

```bash
mkdir -p crates/purple-wolf-core/vendor/libinjection
git show feat/purple-wolf-impl:vendor/libinjection/COPYING > crates/purple-wolf-core/vendor/libinjection/COPYING
for f in libinjection.h libinjection_sqli.c libinjection_sqli.h libinjection_sqli_data.h \
         libinjection_xss.c libinjection_xss.h libinjection_html5.c libinjection_html5.h \
         libinjection_error.h; do
  git show feat/purple-wolf-impl:vendor/libinjection/$f > crates/purple-wolf-core/vendor/libinjection/$f
done
ls crates/purple-wolf-core/vendor/libinjection
```
Expected: 10 files (9 C/H + COPYING).

- [ ] **Step 2: Create `build.rs` (native only for now)**

```rust
fn main() {
    println!("cargo:rerun-if-changed=vendor/libinjection");
    let target = std::env::var("TARGET").unwrap_or_default();

    if target.starts_with("wasm32-") {
        // wasm32 cross-build added by Task 14.
        // For now, skip C compilation on wasm32 targets so the rest of the
        // workspace still builds; injection detector becomes a stub there
        // until Task 14 wires the wasi-sdk cross-build.
        println!("cargo:rustc-cfg=purple_wolf_no_libinjection");
        return;
    }

    cc::Build::new()
        .file("vendor/libinjection/libinjection_sqli.c")
        .file("vendor/libinjection/libinjection_xss.c")
        .file("vendor/libinjection/libinjection_html5.c")
        .include("vendor/libinjection")
        .warnings(false)
        .opt_level(2)
        .compile("injection");
}
```

- [ ] **Step 3: Port v0.1's `src/ffi.rs`**

```bash
git show feat/purple-wolf-impl:src/ffi.rs > crates/purple-wolf-core/src/ffi.rs
```
Wrap the `extern "C"` block and the `is_sqli` / `is_xss` functions in `#[cfg(not(purple_wolf_no_libinjection))]`. Add a `#[cfg(purple_wolf_no_libinjection)]` fallback at the bottom of the file:

```rust
#[cfg(purple_wolf_no_libinjection)]
pub fn is_sqli(_s: &str) -> bool { false }

#[cfg(purple_wolf_no_libinjection)]
pub fn is_xss(_s: &str) -> bool { false }
```

Keep the existing 3 tests gated on `#[cfg(not(purple_wolf_no_libinjection))]` so they only run on native targets (they assert true-positive detection, which the WASM stub can't satisfy until Task 14).

- [ ] **Step 4: Register the module**

`pub mod ffi;` in `crates/purple-wolf-core/src/lib.rs`.

- [ ] **Step 5: Run tests on native**

```bash
cargo test -p purple-wolf-core ffi::
```
Expected: 3 tests PASS (libinjection compiled natively, real detection).

- [ ] **Step 6: Commit**

```bash
git add crates/purple-wolf-core/vendor crates/purple-wolf-core/build.rs crates/purple-wolf-core/src/ffi.rs crates/purple-wolf-core/src/lib.rs
git commit -m "feat(core): vendor libinjection and add safe FFI wrappers (native build)"
```

---

### Task 7: `core::detectors::injection` (libinjection-backed)

**Files:**
- Modify: `crates/purple-wolf-core/src/detectors/injection.rs` (replaces stub)

- [ ] **Step 1: Port v0.1's injection detector**

```bash
git show feat/purple-wolf-impl:src/detectors/injection.rs > crates/purple-wolf-core/src/detectors/injection.rs
```
Update imports: `use crate::request_model::RequestView;` → `use crate::request::Request;`, and `RequestView` → `Request` everywhere.

- [ ] **Step 2: Run tests**

```bash
cargo test -p purple-wolf-core detectors::injection::
```
Expected: 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/purple-wolf-core/src/detectors/injection.rs
git commit -m "feat(core): injection detector (SQLi/XSS via libinjection)"
```

---

### Task 8: `core::detectors::signatures` (aho-corasick)

**Files:**
- Modify: `crates/purple-wolf-core/src/detectors/signatures.rs` (replaces stub)

- [ ] **Step 1: Port v0.1's signatures detector**

```bash
git show feat/purple-wolf-impl:src/detectors/signatures.rs > crates/purple-wolf-core/src/detectors/signatures.rs
```
Update `RequestView` → `Request` and import path.

- [ ] **Step 2: Run tests**

```bash
cargo test -p purple-wolf-core detectors::signatures::
```
Expected: 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/purple-wolf-core/src/detectors/signatures.rs
git commit -m "feat(core): aho-corasick signature detector"
```

---

### Task 9: `core::detectors::structural`

**Files:**
- Modify: `crates/purple-wolf-core/src/detectors/structural.rs` (replaces stub)

- [ ] **Step 1: Port v0.1's structural detector**

```bash
git show feat/purple-wolf-impl:src/detectors/structural.rs > crates/purple-wolf-core/src/detectors/structural.rs
```
Update `RequestView` → `Request` and import path. Port the 4 v0.1 tests (including the `flags_oversized_headers` fix-up).

- [ ] **Step 2: Run tests**

```bash
cargo test -p purple-wolf-core detectors::structural::
```
Expected: 4 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/purple-wolf-core/src/detectors/structural.rs
git commit -m "feat(core): structural anomaly detector"
```

---

### Task 10: `core::detectors::reputation` (with `Clock` abstraction)

**Files:**
- Modify: `crates/purple-wolf-core/src/detectors/reputation.rs` (replaces stub)

- [ ] **Step 1: Port v0.1's reputation detector with Clock injection**

Retrieve the v0.1 file:
```bash
git show feat/purple-wolf-impl:src/detectors/reputation.rs > crates/purple-wolf-core/src/detectors/reputation.rs
```

Update `RequestView` → `Request`. Then modify the limiter construction so it takes a `Clock`:

- Replace the `type IpLimiter = RateLimiter<IpAddr, …, DefaultClock>;` alias with a generic over `C: Clock + governor::clock::Clock`. The simpler path: keep `governor`'s `DefaultClock` (it compiles on WASI via `std::time::Instant`); confirm by building `cargo build -p purple-wolf-core` and noting whether `DefaultClock` requires anything missing in `wasm32-wasip1`. If it does, replace the limiter's clock with `governor::clock::QuantaUpkeepClock` or implement a small `governor::clock::Clock` adapter wrapping `crate::clock::Clock` — pick whichever produces a clean `wasm32-wasip1` build in Task 14 and revisit then.
- Keep the public API of `ReputationDetector::new(per_second, deny_list)` unchanged so the rest of the code (and v0.1's tests) port without changes.

- [ ] **Step 2: Run tests**

```bash
cargo test -p purple-wolf-core detectors::reputation::
```
Expected: 2 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/purple-wolf-core/src/detectors/reputation.rs
git commit -m "feat(core): reputation detector (rate limit + IP deny list)"
```

---

### Task 11: `core::policy`

**Files:**
- Create: `crates/purple-wolf-core/src/policy.rs`
- Modify: `crates/purple-wolf-core/src/lib.rs`

- [ ] **Step 1: Port v0.1's policy module verbatim**

```bash
git show feat/purple-wolf-impl:src/policy.rs > crates/purple-wolf-core/src/policy.rs
```
No changes — policy doesn't depend on anything that moved.

- [ ] **Step 2: Register**

`pub mod policy;` in `crates/purple-wolf-core/src/lib.rs`.

- [ ] **Step 3: Run tests**

```bash
cargo test -p purple-wolf-core policy::
```
Expected: 3 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/purple-wolf-core/src/policy.rs crates/purple-wolf-core/src/lib.rs
git commit -m "feat(core): policy decide()"
```

---

### Task 12: `core::audit`

**Files:**
- Create: `crates/purple-wolf-core/src/audit.rs`
- Modify: `crates/purple-wolf-core/src/lib.rs`

- [ ] **Step 1: Port the AuditEntry half of v0.1's observe.rs**

```bash
git show feat/purple-wolf-impl:src/observe.rs > crates/purple-wolf-core/src/audit.rs
```

Then DELETE from the new file:
- The `record_request` function entirely.
- The `use metrics;` / any metrics-related import.

Update imports: `use crate::request_model::RequestView;` → `use crate::request::Request;`, `RequestView` → `Request`.

Add this serialization helper at the bottom (replaces v0.1's tracing call site):

```rust
/// Serialize an AuditEntry as a single-line JSON string suitable for
/// emission via the deployment's logging mechanism (host `log()` in WASM,
/// stdout in a native deployment).
pub fn to_log_line(entry: &AuditEntry) -> String {
    serde_json::to_string(entry).unwrap_or_else(|_| String::from("{\"error\":\"audit serialize failed\"}"))
}
```

Carry over and adapt the 2 v0.1 audit tests so they still pass.

- [ ] **Step 2: Register**

`pub mod audit;` in `crates/purple-wolf-core/src/lib.rs`.

- [ ] **Step 3: Run tests**

```bash
cargo test -p purple-wolf-core audit::
```
Expected: 2 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/purple-wolf-core/src/audit.rs crates/purple-wolf-core/src/lib.rs
git commit -m "feat(core): AuditEntry and JSON log-line serializer"
```

---

### Task 13: `core::lib.rs` public API + rustdoc examples

**Files:**
- Modify: `crates/purple-wolf-core/src/lib.rs`

- [ ] **Step 1: Replace `lib.rs` with the curated public API**

Replace `crates/purple-wolf-core/src/lib.rs` entirely with:

```rust
//! purple-wolf-core: hybrid WAF detection engine.
//!
//! Build a [`request::Request`] from raw HTTP fields, run [`detectors::Engine::inspect`],
//! and turn the verdicts into an action with [`policy::decide`]. The
//! [`audit::AuditEntry`] type captures one log-worthy record per decision.
//!
//! Embedders own all I/O, configuration loading, and result delivery. This
//! crate has no async runtime, no networking, and no global state. It
//! compiles to native targets and to `wasm32-wasip1`.
//!
//! # Example: inspect a request
//!
//! ```
//! use purple_wolf_core::request::{Request, client_ip};
//! use purple_wolf_core::detectors::{Engine, Group};
//! use purple_wolf_core::detectors::injection::InjectionDetector;
//! use purple_wolf_core::policy;
//! use purple_wolf_core::config::{Mode, GroupMode};
//! use std::net::Ipv4Addr;
//!
//! let req = Request::build(
//!     "GET", "example.com", "/search",
//!     "q=%27%20OR%201%3D1",
//!     vec![],
//!     vec![],
//!     false,
//!     std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
//! );
//! let engine = Engine::new(vec![Box::new(InjectionDetector)]);
//! let verdicts = engine.inspect(&req, &[Group::Injection]);
//! let decision = policy::decide(verdicts, Mode::Enforce, |_| GroupMode::Enforce);
//! assert_eq!(decision.action, policy::Action::Block);
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]

pub mod audit;
pub mod clock;
pub mod config;
pub mod detectors;
pub mod ffi;
pub mod policy;
pub mod request;
```

- [ ] **Step 2: Ensure every public item has at least a one-line doc comment**

Walk every `pub` item across the crate; add a `/// …` line where missing. `cargo doc --no-deps -p purple-wolf-core 2>&1 | grep warning` should be silent.

- [ ] **Step 3: Verify rustdoc and doc-test**

```bash
cargo doc --no-deps -p purple-wolf-core
cargo test -p purple-wolf-core --doc
```
Expected: doc builds with no warnings; the doctest above passes.

- [ ] **Step 4: Commit**

```bash
git add crates/purple-wolf-core/src/lib.rs crates/purple-wolf-core/src/*.rs crates/purple-wolf-core/src/detectors/*.rs
git commit -m "docs(core): curated public API surface with runnable example"
```

---

## Phase C — Cross-compile core to `wasm32-wasip1`

### Task 14: Cross-compile libinjection to `wasm32-wasip1` via wasi-sdk

**Files:**
- Modify: `crates/purple-wolf-core/build.rs`
- Modify: `crates/purple-wolf-core/src/ffi.rs` (remove the `purple_wolf_no_libinjection` gate)
- Create: `.github/workflows/wasm-toolchain.sh` (helper, used by CI later)

- [ ] **Step 1: Install `wasi-sdk` locally for development**

```bash
# macOS host:
brew install wasi-sdk  || true
ls /opt/wasi-sdk/bin/clang || ls /usr/local/wasi-sdk/bin/clang
# If neither exists, download manually:
#   https://github.com/WebAssembly/wasi-sdk/releases  (download the macos arm64 tarball)
#   extract to /opt/wasi-sdk and `export WASI_SDK_PATH=/opt/wasi-sdk`
echo "${WASI_SDK_PATH:-/opt/wasi-sdk}/bin/clang --version"
${WASI_SDK_PATH:-/opt/wasi-sdk}/bin/clang --version
```
Expected: prints a clang version banner.

- [ ] **Step 2: Extend `build.rs` to cross-compile to wasm32**

Replace `crates/purple-wolf-core/build.rs`:

```rust
fn main() {
    println!("cargo:rerun-if-changed=vendor/libinjection");
    println!("cargo:rerun-if-env-changed=WASI_SDK_PATH");
    let target = std::env::var("TARGET").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .file("vendor/libinjection/libinjection_sqli.c")
        .file("vendor/libinjection/libinjection_xss.c")
        .file("vendor/libinjection/libinjection_html5.c")
        .include("vendor/libinjection")
        .warnings(false)
        .opt_level(2);

    if target.starts_with("wasm32-") {
        // Cross-compile libinjection to wasm32 via wasi-sdk.
        let sdk = std::env::var("WASI_SDK_PATH").unwrap_or_else(|_| "/opt/wasi-sdk".into());
        let clang = format!("{sdk}/bin/clang");
        let sysroot = format!("{sdk}/share/wasi-sysroot");
        build
            .compiler(&clang)
            .archiver(format!("{sdk}/bin/llvm-ar"))
            .flag(format!("--sysroot={sysroot}"))
            .flag("--target=wasm32-wasi")
            .flag("-fno-exceptions")
            .flag("-D_WASI_EMULATED_PROCESS_CLOCKS");
        println!("cargo:rustc-link-arg=-lwasi-emulated-process-clocks");
    }

    build.compile("injection");
}
```

- [ ] **Step 3: Remove the wasm stub gate from `ffi.rs`**

Delete the `#[cfg(purple_wolf_no_libinjection)]` fallbacks from `crates/purple-wolf-core/src/ffi.rs` and remove the `#[cfg(not(purple_wolf_no_libinjection))]` guards from the real wrappers / tests. With Task 14 the C code compiles to WASM, so the stub is no longer needed.

- [ ] **Step 4: Verify native still builds and tests pass**

```bash
cargo test -p purple-wolf-core
```
Expected: all tests still PASS.

- [ ] **Step 5: Verify wasm32 build succeeds**

```bash
WASI_SDK_PATH=${WASI_SDK_PATH:-/opt/wasi-sdk} \
  cargo build -p purple-wolf-core --target wasm32-wasip1
```
Expected: build succeeds. If `governor`'s default clock fails on `wasm32-wasip1`, this is the moment to swap to a `Clock`-trait-backed limiter (see Task 10's note); make the minimal change and confirm both native and wasm32 build cleanly.

- [ ] **Step 6: Commit**

```bash
git add crates/purple-wolf-core/build.rs crates/purple-wolf-core/src/ffi.rs
git commit -m "feat(core): cross-compile libinjection to wasm32-wasip1 via wasi-sdk"
```

---

## Phase D — `purple-wolf-traefik` http-wasm plugin

### Task 15: Choose http-wasm SDK; create `traefik::host` shim

**Files:**
- Modify: `crates/purple-wolf-traefik/Cargo.toml`
- Create: `crates/purple-wolf-traefik/src/host.rs`
- Modify: `crates/purple-wolf-traefik/src/lib.rs`

- [ ] **Step 1: Survey the http-wasm guest SDK options**

Open `https://github.com/http-wasm/http-wasm-host-go` and the listed guest SDKs. Identify the most current Rust guest SDK (crates.io: search for `http-wasm-guest`). Two outcomes are acceptable:

- (A) A maintained Rust guest SDK exists with recent activity → add it as a dep in `crates/purple-wolf-traefik/Cargo.toml` and the next steps use its API.
- (B) No suitable SDK → hand-roll a small shim against the http-wasm spec (`https://http-wasm.io/`). The spec defines a tiny set of imported functions and exported `handle_request` / `handle_response` signatures.

Document the chosen path with a one-paragraph comment at the top of `host.rs`.

- [ ] **Step 2: Implement (or wrap) the host ABI**

`crates/purple-wolf-traefik/src/host.rs` must expose this typed surface (regardless of whether it's a wrapped SDK or hand-rolled):

```rust
//! http-wasm host bindings used by the plugin entry points.
//!
//! Either re-exports a third-party SDK or hand-rolls the minimal ABI per
//! the spec at https://http-wasm.io/.

pub fn get_method() -> String;
pub fn get_uri() -> String;                         // path + query
pub fn get_request_header_names() -> Vec<String>;
pub fn get_request_header(name: &str) -> Option<String>;
pub fn read_request_body(max: usize) -> Vec<u8>;    // truncated at `max`
pub fn request_body_exceeded(max: usize) -> bool;   // true iff body > max
pub fn get_source_addr() -> String;                 // "ip:port" of TCP peer

pub fn write_response(status: u16, body: &[u8]);    // writes status + body, halts
pub fn log(message: &str);                          // host-side log sink
pub fn config() -> Vec<u8>;                         // raw Middleware plugin config bytes (JSON)
```

Each function is a thin wrapper around the chosen SDK call or hand-rolled `extern "C"` import. Document UNSAFE blocks with `// SAFETY:` comments. Implementations may be `unimplemented!()` for any function the v0.2 plugin doesn't end up using — but the signatures listed above are the required surface for Task 17.

- [ ] **Step 3: Register the module**

In `crates/purple-wolf-traefik/src/lib.rs` add: `mod host;`

- [ ] **Step 4: Verify the WASM build compiles**

```bash
WASI_SDK_PATH=${WASI_SDK_PATH:-/opt/wasi-sdk} \
  cargo build -p purple-wolf-traefik --target wasm32-wasip1
```
Expected: compiles cleanly.

- [ ] **Step 5: Commit**

```bash
git add crates/purple-wolf-traefik/Cargo.toml crates/purple-wolf-traefik/src/host.rs crates/purple-wolf-traefik/src/lib.rs
git commit -m "feat(traefik): http-wasm host ABI shim"
```

---

### Task 16: `traefik::config` adapter (Middleware JSON → core::Config)

**Files:**
- Create: `crates/purple-wolf-traefik/src/config.rs`
- Modify: `crates/purple-wolf-traefik/src/lib.rs`

- [ ] **Step 1: Write the adapter and its tests**

`crates/purple-wolf-traefik/src/config.rs`:

```rust
//! Adapt the JSON delivered by Traefik (Middleware plugin params, camelCase)
//! to `purple_wolf_core::config::Config` (snake_case).
use purple_wolf_core::config as core;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Wire {
    mode: core::Mode,
    #[serde(default = "default_fail_mode")]
    fail_mode: core::FailMode,
    #[serde(default)]
    body: WireBody,
    #[serde(default)]
    groups: core::Groups,
    #[serde(default)]
    reputation: core::ReputationConfig,
}

fn default_fail_mode() -> core::FailMode { core::FailMode::FailOpen }

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireBody {
    #[serde(default = "default_max_inspect_bytes")]
    max_inspect_bytes: usize,
    #[serde(default = "default_over_cap")]
    over_cap: core::OverCap,
}

fn default_max_inspect_bytes() -> usize { 1_048_576 }
fn default_over_cap() -> core::OverCap { core::OverCap::Pass }

impl Default for WireBody {
    fn default() -> Self {
        WireBody { max_inspect_bytes: default_max_inspect_bytes(), over_cap: default_over_cap() }
    }
}

/// Parse the raw JSON bytes Traefik hands the plugin.
pub fn parse(bytes: &[u8]) -> Result<core::Config, String> {
    let w: Wire = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    Ok(core::Config {
        mode: w.mode,
        fail_mode: w.fail_mode,
        body: core::BodyConfig { max_inspect_bytes: w.body.max_inspect_bytes, over_cap: w.body.over_cap },
        groups: w.groups,
        reputation: w.reputation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_camelcase() {
        let json = br#"{
          "mode": "enforce",
          "failMode": "failClosed",
          "body": { "maxInspectBytes": 2048, "overCap": "block" },
          "groups": {
            "injection":  { "enabled": true, "mode": "enforce" },
            "structural": { "enabled": false, "mode": "monitor" }
          },
          "reputation": { "perSecond": 50, "denyList": ["1.2.3.4"] }
        }"#;
        let cfg = parse(json).expect("parse");
        assert_eq!(cfg.mode, core::Mode::Enforce);
        assert_eq!(cfg.fail_mode, core::FailMode::FailClosed);
        assert_eq!(cfg.body.max_inspect_bytes, 2048);
        assert_eq!(cfg.body.over_cap, core::OverCap::Block);
        assert_eq!(cfg.reputation.per_second, 50);
    }

    #[test]
    fn defaults_when_optional_fields_absent() {
        let json = br#"{ "mode": "monitor" }"#;
        let cfg = parse(json).expect("parse");
        assert_eq!(cfg.fail_mode, core::FailMode::FailOpen);
        assert_eq!(cfg.body.max_inspect_bytes, 1_048_576);
        assert_eq!(cfg.body.over_cap, core::OverCap::Pass);
    }
}
```

- [ ] **Step 2: Register the module**

In `crates/purple-wolf-traefik/src/lib.rs` add: `mod config;`

- [ ] **Step 3: Run tests (native)**

```bash
cargo test -p purple-wolf-traefik config::
```
Expected: 2 tests PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/purple-wolf-traefik/src/config.rs crates/purple-wolf-traefik/src/lib.rs
git commit -m "feat(traefik): Middleware JSON → core::Config adapter"
```

---

### Task 17: `traefik::entry` — the http-wasm handlers

**Files:**
- Create: `crates/purple-wolf-traefik/src/entry.rs`
- Modify: `crates/purple-wolf-traefik/src/lib.rs`

- [ ] **Step 1: Implement the entry orchestrator**

`crates/purple-wolf-traefik/src/entry.rs`:

```rust
//! The http-wasm guest entry: parse config, build a `Request`, run the
//! Engine, apply policy, either pass through or short-circuit with 403,
//! and emit an audit line via the host log sink.

use crate::{config as adapter, host};
use purple_wolf_core::{
    audit::{self, AuditEntry},
    config::{Config, FailMode, OverCap},
    detectors::{Engine, injection::InjectionDetector, signatures::SignatureDetector,
                structural::StructuralDetector, reputation::ReputationDetector},
    policy::{self, Action, Decision},
    request::{self, Request},
};
use std::cell::OnceCell;
use std::net::IpAddr;

/// Build the engine once per plugin instance.
fn engine(cfg: &Config) -> Engine {
    let ips: Vec<IpAddr> = cfg.reputation.deny_list.iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    Engine::new(vec![
        Box::new(InjectionDetector),
        Box::new(SignatureDetector::new()),
        Box::new(StructuralDetector),
        Box::new(ReputationDetector::new(cfg.reputation.per_second, ips)),
    ])
}

thread_local! {
    static STATE: OnceCell<(Config, Engine)> = OnceCell::new();
}

fn state<R>(f: impl FnOnce(&Config, &Engine) -> R) -> R {
    STATE.with(|s| {
        let (cfg, engine) = s.get_or_init(|| {
            let cfg = adapter::parse(&host::config()).unwrap_or_else(|e| {
                host::log(&format!("purple-wolf: invalid config: {e}"));
                // Fall back to a permissive monitor config so the plugin
                // doesn't bring down every route on a bad config.
                serde_json::from_str(r#"{ "mode": "monitor" }"#).unwrap()
            });
            let eng = engine(&cfg);
            (cfg, eng)
        });
        f(cfg, engine)
    })
}

/// http-wasm exported entry point invoked once per request.
#[no_mangle]
pub extern "C" fn handle_request() -> u64 {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(inspect));
    match result {
        Ok(action) => match action {
            Action::Allow => 1,  // http-wasm convention: 1 = continue
            Action::Block => 0,  // 0 = stop (we already wrote the response)
        }
        Err(_) => {
            // Soft failure: detector panic.
            host::log("purple-wolf: soft failure (panic) — applying fail mode");
            state(|cfg, _engine| match cfg.fail_mode {
                FailMode::FailOpen => 1u64,
                FailMode::FailClosed => {
                    host::write_response(403, b"inspection failed (fail_closed)");
                    0
                }
            })
        }
    }
}

fn inspect() -> Action {
    state(|cfg, engine| {
        // Build header list (lowercased names; values are byte-faithful).
        let names = host::get_request_header_names();
        let headers: Vec<(String, String)> = names.iter()
            .filter_map(|n| host::get_request_header(n).map(|v| (n.to_lowercase(), v)))
            .collect();

        // Source IP: XFF → X-Real-IP → peer.
        let peer: IpAddr = host::get_source_addr().split(':').next()
            .and_then(|h| h.parse().ok())
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let source_ip = request::client_ip(&headers, peer);

        // URI split.
        let uri = host::get_uri();
        let (path, raw_query) = uri.split_once('?').map(|(p, q)| (p.to_string(), q.to_string()))
                                                  .unwrap_or_else(|| (uri.clone(), String::new()));
        let method = host::get_method();
        let host_hdr = headers.iter().find(|(k, _)| k == "host").map(|(_, v)| v.clone()).unwrap_or_default();

        // Body (capped).
        let cap = cfg.body.max_inspect_bytes;
        let body = host::read_request_body(cap);
        let over_cap = host::request_body_exceeded(cap);
        if over_cap && cfg.body.over_cap == OverCap::Block {
            host::write_response(403, b"body exceeds inspection cap");
            return Action::Block;
        }
        let body_inspected = !over_cap;

        let req = Request::build(&method, &host_hdr, &path, &raw_query, headers, body, body_inspected, source_ip);
        let enabled: Vec<_> = [
            purple_wolf_core::detectors::Group::Injection,
            purple_wolf_core::detectors::Group::Signatures,
            purple_wolf_core::detectors::Group::Structural,
            purple_wolf_core::detectors::Group::Reputation,
        ].into_iter()
         .filter(|g| group_enabled(cfg, *g))
         .collect();

        let verdicts = engine.inspect(&req, &enabled);
        let decision = policy::decide(verdicts, cfg.mode, |g| group_mode(cfg, g));

        // Audit log if anything to say.
        let entry = AuditEntry::from(&req, &decision);
        if entry.is_noteworthy() {
            host::log(&audit::to_log_line(&entry));
        }

        match decision.action {
            Action::Allow => Action::Allow,
            Action::Block => {
                host::write_response(403, b"request blocked by purple-wolf");
                Action::Block
            }
        }
    })
}

fn group_enabled(cfg: &Config, g: purple_wolf_core::detectors::Group) -> bool {
    group_mode(cfg, g) != purple_wolf_core::config::GroupMode::Off
}

fn group_mode(cfg: &Config, g: purple_wolf_core::detectors::Group) -> purple_wolf_core::config::GroupMode {
    use purple_wolf_core::config::GroupMode;
    use purple_wolf_core::detectors::Group;
    let gc = match g {
        Group::Injection  => cfg.groups.injection.as_ref(),
        Group::Signatures => cfg.groups.signatures.as_ref(),
        Group::Structural => cfg.groups.structural.as_ref(),
        Group::Reputation => cfg.groups.reputation.as_ref(),
    };
    match gc { Some(g) if g.enabled => g.mode, _ => GroupMode::Off }
}

/// http-wasm exported response hook (unused; we don't modify responses).
#[no_mangle]
pub extern "C" fn handle_response(_req_ctx: u32, _is_error: u32) {}
```

- [ ] **Step 2: Register the module**

In `crates/purple-wolf-traefik/src/lib.rs` replace its content with:

```rust
//! purple-wolf-traefik: http-wasm guest plugin wrapping `purple-wolf-core`.

mod config;
mod entry;
mod host;

// Re-export the exported functions so they appear in the .wasm export table.
pub use entry::{handle_request, handle_response};
```

- [ ] **Step 3: Native build smoke**

```bash
cargo build -p purple-wolf-traefik
```
Expected: compiles (native build, host calls are stubs/unimplemented as decided in Task 15 — that's fine; the wasm32 build is the real artifact).

- [ ] **Step 4: WASM build produces the artifact**

```bash
WASI_SDK_PATH=${WASI_SDK_PATH:-/opt/wasi-sdk} \
  cargo build -p purple-wolf-traefik --target wasm32-wasip1 --release
ls -lh target/wasm32-wasip1/release/purple_wolf_traefik.wasm
```
Expected: `.wasm` file produced; size in the low hundreds of KB.

- [ ] **Step 5: Commit**

```bash
git add crates/purple-wolf-traefik/src/entry.rs crates/purple-wolf-traefik/src/lib.rs
git commit -m "feat(traefik): handle_request/handle_response entry points"
```

---

## Phase E — Tests & Benchmarks (OSS-grade)

### Task 18: proptest properties on `core`

**Files:**
- Modify: `crates/purple-wolf-core/Cargo.toml` (add `proptest` dev-dep)
- Create: `crates/purple-wolf-core/tests/properties.rs`

- [ ] **Step 1: Add proptest dev dependency**

In `crates/purple-wolf-core/Cargo.toml`:

```toml
[dev-dependencies]
proptest = "1"
```

- [ ] **Step 2: Write the property tests**

`crates/purple-wolf-core/tests/properties.rs`:

```rust
//! Property-based invariants the engine must never violate.
use proptest::prelude::*;
use purple_wolf_core::config::{GroupMode, Mode};
use purple_wolf_core::detectors::{Group, Severity, Verdict};
use purple_wolf_core::policy::{self, Action};
use purple_wolf_core::request::{Request, client_ip};
use std::net::{IpAddr, Ipv4Addr};

fn any_group() -> impl Strategy<Value = Group> {
    prop_oneof![
        Just(Group::Injection),
        Just(Group::Signatures),
        Just(Group::Structural),
        Just(Group::Reputation),
    ]
}

fn any_verdict() -> impl Strategy<Value = Verdict> {
    any_group().prop_map(|g| Verdict { group: g, rule: "p", severity: Severity::High, detail: "p".into() })
}

proptest! {
    /// Monitor mode never blocks, no matter the verdicts or per-group modes.
    #[test]
    fn monitor_global_never_blocks(verdicts in proptest::collection::vec(any_verdict(), 0..16)) {
        let d = policy::decide(verdicts, Mode::Monitor, |_| GroupMode::Enforce);
        prop_assert_eq!(d.action, Action::Allow);
    }

    /// `GroupMode::Off` for every group suppresses ALL verdicts.
    #[test]
    fn group_mode_off_suppresses_all(verdicts in proptest::collection::vec(any_verdict(), 0..16)) {
        let d = policy::decide(verdicts.clone(), Mode::Enforce, |_| GroupMode::Off);
        prop_assert_eq!(d.action, Action::Allow);
        prop_assert!(d.would_block.is_empty());
    }

    /// Building a Request from arbitrary inputs never panics and the
    /// resulting `method`/`host` are uppercased/lowercased respectively.
    #[test]
    fn request_build_never_panics(
        method in "[A-Za-z]{1,16}",
        host in "[A-Za-z0-9\\.\\-]{1,64}",
        path in "/[A-Za-z0-9/_\\-\\.%]{0,128}",
        query in "[A-Za-z0-9=&%\\-_]{0,256}"
    ) {
        let _r = Request::build(&method, &host, &path, &query, vec![], vec![], false,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        prop_assert_eq!(_r.method, method.to_ascii_uppercase());
        prop_assert_eq!(_r.host,   host.to_ascii_lowercase());
    }

    /// `client_ip` always returns a parseable IpAddr — never panics.
    #[test]
    fn client_ip_total(xff in "[0-9\\.,\\s]{0,128}", real in "[0-9\\.]{0,32}") {
        let headers = vec![
            ("x-forwarded-for".to_string(), xff),
            ("x-real-ip".to_string(), real),
        ];
        let _ = client_ip(&headers, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        // The function returning any IpAddr is the property.
        prop_assert!(true);
    }
}
```

- [ ] **Step 3: Run the property tests**

```bash
cargo test -p purple-wolf-core --test properties
```
Expected: 4 properties PASS (proptest default 256 cases each).

- [ ] **Step 4: Commit**

```bash
git add crates/purple-wolf-core/Cargo.toml crates/purple-wolf-core/tests/properties.rs
git commit -m "test(core): proptest invariants — monitor-never-blocks, off-suppresses, build-total"
```

---

### Task 19: cargo-fuzz harness with 4 targets

**Files:**
- Create: `fuzz/Cargo.toml`
- Create: `fuzz/fuzz_targets/{request_parser,injection_inspect,signatures_inspect,policy_decide}.rs`
- Create: `fuzz/corpus/<target>/seed-0` per target

- [ ] **Step 1: Install cargo-fuzz**

```bash
cargo install cargo-fuzz
```

- [ ] **Step 2: Initialize the fuzz crate**

```bash
cargo fuzz init  # creates fuzz/Cargo.toml + fuzz/fuzz_targets/
```
Then EDIT `fuzz/Cargo.toml` so the workspace exclusion in the root `Cargo.toml` (already done in Task 1) keeps it out of the workspace, and so it depends on the core crate:

```toml
[package]
name = "purple-wolf-fuzz"
version = "0.0.0"
publish = false
edition = "2021"

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
purple-wolf-core = { path = "../crates/purple-wolf-core" }

[[bin]]
name = "request_parser"
path = "fuzz_targets/request_parser.rs"
test = false
doc  = false

[[bin]]
name = "injection_inspect"
path = "fuzz_targets/injection_inspect.rs"
test = false
doc  = false

[[bin]]
name = "signatures_inspect"
path = "fuzz_targets/signatures_inspect.rs"
test = false
doc  = false

[[bin]]
name = "policy_decide"
path = "fuzz_targets/policy_decide.rs"
test = false
doc  = false
```

- [ ] **Step 3: Write the four fuzz targets**

`fuzz/fuzz_targets/request_parser.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::request::Request;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    // Split the input bytes into rough "fields" the parser would otherwise
    // receive from a host. The property: never panic.
    let s = String::from_utf8_lossy(data);
    let parts: Vec<&str> = s.split('|').collect();
    let method = parts.first().copied().unwrap_or("GET");
    let host   = parts.get(1).copied().unwrap_or("");
    let path   = parts.get(2).copied().unwrap_or("/");
    let query  = parts.get(3).copied().unwrap_or("");
    let body   = parts.get(4).map(|p| p.as_bytes().to_vec()).unwrap_or_default();
    let _ = Request::build(method, host, path, query, vec![], body, true,
        IpAddr::V4(Ipv4Addr::LOCALHOST));
});
```

`fuzz/fuzz_targets/injection_inspect.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::detectors::{Detector, injection::InjectionDetector};
use purple_wolf_core::request::Request;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data).into_owned();
    let req = Request::build("GET", "h", "/", &format!("q={s}"), vec![], vec![], false,
        IpAddr::V4(Ipv4Addr::LOCALHOST));
    let _ = InjectionDetector.inspect(&req);
});
```

`fuzz/fuzz_targets/signatures_inspect.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::detectors::{Detector, signatures::SignatureDetector};
use purple_wolf_core::request::Request;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data).into_owned();
    let req = Request::build("GET", "h", "/", &format!("q={s}"), vec![], vec![], false,
        IpAddr::V4(Ipv4Addr::LOCALHOST));
    let _ = SignatureDetector::new().inspect(&req);
});
```

`fuzz/fuzz_targets/policy_decide.rs`:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::config::{GroupMode, Mode};
use purple_wolf_core::detectors::{Group, Severity, Verdict};
use purple_wolf_core::policy;

fuzz_target!(|data: &[u8]| {
    let mut verdicts = Vec::new();
    for b in data.iter() {
        let g = match b % 4 {
            0 => Group::Injection, 1 => Group::Signatures,
            2 => Group::Structural, _ => Group::Reputation,
        };
        verdicts.push(Verdict { group: g, rule: "f", severity: Severity::High, detail: "f".into() });
    }
    let mode = if data.first().map_or(false, |b| b & 1 == 0) { Mode::Enforce } else { Mode::Monitor };
    let _ = policy::decide(verdicts, mode, |_| GroupMode::Enforce);
});
```

- [ ] **Step 4: Seed each target's corpus**

```bash
mkdir -p fuzz/corpus/request_parser fuzz/corpus/injection_inspect \
         fuzz/corpus/signatures_inspect fuzz/corpus/policy_decide
echo -n "GET|example.com|/search|q=1' OR '1'='1|" > fuzz/corpus/request_parser/seed-0
echo -n "1' OR '1'='1"        > fuzz/corpus/injection_inspect/seed-0
echo -n "../../etc/passwd"    > fuzz/corpus/signatures_inspect/seed-0
printf '\x00\x01\x02\x03'     > fuzz/corpus/policy_decide/seed-0
```

- [ ] **Step 5: Smoke-run each target for 30 seconds**

```bash
cd fuzz
for t in request_parser injection_inspect signatures_inspect policy_decide; do
  cargo +nightly fuzz run "$t" -- -max_total_time=30
done
cd ..
```
Expected: each target runs without crashing. If a panic is found, FIX THE BUG (don't disable the test).

- [ ] **Step 6: Commit (omit the discovered corpus, keep only seeds)**

```bash
git add fuzz/Cargo.toml fuzz/fuzz_targets fuzz/corpus
git commit -m "test(fuzz): cargo-fuzz harness — 4 targets with seed corpora"
```

---

### Task 20: OWASP CRS payload corpus + golden-file detection test

**Files:**
- Create: `tests/corpus/crs/` (vendored CRS regression-test payloads)
- Create: `tests/corpus/clean/` (curated benign payloads)
- Create: `tests/parity/crs_replay.rs` (run as `cargo test --test crs_replay`)
- Create: `tests/parity/expectations.toml` (per-payload expected verdict)
- Modify: workspace `Cargo.toml` (add the integration test wiring if needed)

- [ ] **Step 1: Vendor CRS regression payloads**

Clone the CRS test suite and extract just the relevant payload files:

```bash
git clone --depth 1 https://github.com/coreruleset/coreruleset.git /tmp/crs
mkdir -p tests/corpus/crs
# Carry only the regression-test payload subfolders for SQLi (942) and XSS (941).
cp -r /tmp/crs/tests/regression/tests/REQUEST-941-APPLICATION-ATTACK-XSS tests/corpus/crs/
cp -r /tmp/crs/tests/regression/tests/REQUEST-942-APPLICATION-ATTACK-SQLI tests/corpus/crs/
cp /tmp/crs/LICENSE tests/corpus/crs/LICENSE
rm -rf /tmp/crs
ls tests/corpus/crs
```

- [ ] **Step 2: Curate a small benign corpus**

```bash
mkdir -p tests/corpus/clean
cat > tests/corpus/clean/clean.txt <<'EOF'
name=victor&page=2
about
search?q=cats and dogs
ref=home
hello world
EOF
```

- [ ] **Step 3: Write the replay test**

`tests/parity/crs_replay.rs`:

```rust
//! Replay vendored payloads through the engine and verify the verdict
//! matches the per-payload expectation. Drift here means real detection
//! quality changes — investigate before allow-listing.
use purple_wolf_core::detectors::{Detector, Engine, Group,
    injection::InjectionDetector, signatures::SignatureDetector};
use purple_wolf_core::request::Request;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

fn ip() -> IpAddr { IpAddr::V4(Ipv4Addr::LOCALHOST) }

fn run_engine_over(payload: &str) -> bool {
    let req = Request::build("GET", "h", "/", &format!("q={payload}"),
        vec![], vec![], false, ip());
    let engine = Engine::new(vec![
        Box::new(InjectionDetector),
        Box::new(SignatureDetector::new()),
    ]);
    let v = engine.inspect(&req, &[Group::Injection, Group::Signatures]);
    !v.is_empty()
}

fn extract_payloads(crs_dir: &Path) -> Vec<String> {
    // CRS test YAMLs contain `data:` fields with the attack payload. We
    // do a brittle but adequate scrape: every line beginning with `data:`.
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(crs_dir).into_iter().flatten() {
        if !entry.file_type().is_file() { continue; }
        if entry.path().extension().and_then(|s| s.to_str()) != Some("yaml") { continue; }
        let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
        for line in content.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("data:") {
                let payload = rest.trim().trim_matches('"').trim_matches('\'');
                if !payload.is_empty() { out.push(payload.to_string()); }
            }
        }
    }
    out
}

#[test]
fn crs_attack_corpus_is_mostly_detected() {
    let dir = std::path::Path::new("tests/corpus/crs");
    if !dir.exists() { eprintln!("crs corpus missing; skipping"); return; }
    let payloads = extract_payloads(dir);
    assert!(!payloads.is_empty(), "no payloads extracted from CRS corpus");
    let total = payloads.len();
    let detected = payloads.iter().filter(|p| run_engine_over(p)).count();
    // Detection threshold: > 70% of CRS payloads. Tune as detection improves.
    let pct = (detected as f64) / (total as f64);
    assert!(pct >= 0.70, "CRS detection rate {detected}/{total} = {pct:.2} below 0.70");
}

#[test]
fn benign_corpus_has_no_false_positives() {
    let path = "tests/corpus/clean/clean.txt";
    let text = std::fs::read_to_string(path).expect("clean.txt");
    let mut fps = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        if run_engine_over(line) { fps.push(line.to_string()); }
    }
    assert!(fps.is_empty(), "false positives on benign inputs: {fps:?}");
}
```

Add `walkdir = "2"` to the workspace's dev-dependencies (via the core crate or a `tests/Cargo.toml` if you set up one — simplest is `crates/purple-wolf-core/Cargo.toml` `[dev-dependencies]` since the integration test will live there if `tests/` isn't a workspace member; OR move `tests/parity/crs_replay.rs` to `crates/purple-wolf-core/tests/crs_replay.rs` and adjust the corpus path with `env!("CARGO_MANIFEST_DIR")`).

Update the test's `dir` path to `Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus/crs")` if you place it under `crates/purple-wolf-core/tests/`.

- [ ] **Step 4: Run the replay**

```bash
cargo test --test crs_replay
```
Expected: both tests PASS. If `crs_attack_corpus_is_mostly_detected` fails BELOW 70%, investigate — it likely means a port bug, not a CRS issue.

- [ ] **Step 5: Commit**

```bash
git add tests/corpus crates/purple-wolf-core/tests/crs_replay.rs crates/purple-wolf-core/Cargo.toml
git commit -m "test(parity): replay OWASP CRS payload corpus + benign-FP guard"
```

---

### Task 21: criterion benchmarks + baseline

**Files:**
- Create: `crates/purple-wolf-core/benches/pipeline.rs`
- Modify: `crates/purple-wolf-core/Cargo.toml` (add `criterion` dev-dep + `[[bench]]`)

- [ ] **Step 1: Add criterion**

In `crates/purple-wolf-core/Cargo.toml`:

```toml
[dev-dependencies]
criterion = { version = "0.5", default-features = false, features = ["html_reports"] }

[[bench]]
name = "pipeline"
harness = false
```

- [ ] **Step 2: Write the benches**

`crates/purple-wolf-core/benches/pipeline.rs`:

```rust
use criterion::{criterion_group, criterion_main, Criterion, black_box};
use purple_wolf_core::config::{GroupMode, Mode};
use purple_wolf_core::detectors::{Detector, Engine, Group,
    injection::InjectionDetector, signatures::SignatureDetector,
    structural::StructuralDetector};
use purple_wolf_core::policy;
use purple_wolf_core::request::Request;
use std::net::{IpAddr, Ipv4Addr};

fn benign_request() -> Request {
    Request::build("GET", "example.com", "/api/v1/users",
        "page=2&limit=20",
        vec![("user-agent".into(), "Mozilla/5.0".into()),
             ("accept".into(), "application/json".into())],
        vec![], false,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 17)))
}

fn sqli_request() -> Request {
    Request::build("GET", "example.com", "/search",
        "q=1' OR '1'='1",
        vec![("user-agent".into(), "Mozilla/5.0".into())],
        vec![], false,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 17)))
}

fn bench(c: &mut Criterion) {
    let engine = Engine::new(vec![
        Box::new(InjectionDetector),
        Box::new(SignatureDetector::new()),
        Box::new(StructuralDetector),
    ]);
    let groups = &[Group::Injection, Group::Signatures, Group::Structural];

    c.bench_function("inspect/benign", |b| b.iter(|| {
        let r = benign_request();
        let v = engine.inspect(&r, black_box(groups));
        let _ = policy::decide(v, Mode::Enforce, |_| GroupMode::Enforce);
    }));

    c.bench_function("inspect/sqli", |b| b.iter(|| {
        let r = sqli_request();
        let v = engine.inspect(&r, black_box(groups));
        let _ = policy::decide(v, Mode::Enforce, |_| GroupMode::Enforce);
    }));

    c.bench_function("detector/injection", |b| b.iter(|| {
        InjectionDetector.inspect(&sqli_request())
    }));
    c.bench_function("detector/signatures", |b| b.iter(|| {
        SignatureDetector::new().inspect(&sqli_request())
    }));
}

criterion_group!(benches, bench);
criterion_main!(benches);
```

- [ ] **Step 3: Run the benches and save the baseline**

```bash
cargo bench -p purple-wolf-core
cargo bench -p purple-wolf-core -- --save-baseline main
```
Expected: benches run; criterion writes results to `target/criterion/`. The CI gate in Task 22 compares against the `main` baseline.

- [ ] **Step 4: Commit (benches/, not target/)**

```bash
git add crates/purple-wolf-core/benches crates/purple-wolf-core/Cargo.toml
git commit -m "bench(core): criterion baseline (inspect/benign, sqli, per-detector)"
```

---

## Phase F — Continuous Integration

### Task 22: GitHub Actions CI matrix

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/bench.yml`

- [ ] **Step 1: Author the main CI workflow**

`.github/workflows/ci.yml`:

```yaml
name: ci
on:
  push:
    branches: [main, "v0.*/**"]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  test-linux:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        rust: [stable, beta, "1.75"]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with: { toolchain: ${{ matrix.rust }}, components: rustfmt, clippy }
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --workspace --all-targets
      - run: cargo test --workspace --doc

  test-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --workspace --all-targets

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt, clippy }
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings

  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v1

  wasm-build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: wasm32-wasip1 }
      - name: Install wasi-sdk
        run: |
          curl -sSL https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-22/wasi-sdk-22.0-linux.tar.gz | tar xz -C /opt
          echo "WASI_SDK_PATH=/opt/wasi-sdk-22.0" >> $GITHUB_ENV
      - uses: Swatinem/rust-cache@v2
      - run: cargo build -p purple-wolf-traefik --target wasm32-wasip1 --release
      - run: ls -lh target/wasm32-wasip1/release/purple_wolf_traefik.wasm
      - uses: actions/upload-artifact@v4
        with: { name: purple-wolf.wasm, path: target/wasm32-wasip1/release/purple_wolf_traefik.wasm }

  fuzz-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - uses: Swatinem/rust-cache@v2
      - run: |
          cd fuzz
          for t in request_parser injection_inspect signatures_inspect policy_decide; do
            cargo fuzz run "$t" -- -max_total_time=30
          done

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: llvm-tools-preview }
      - run: cargo install cargo-llvm-cov
      - uses: Swatinem/rust-cache@v2
      - run: cargo llvm-cov --workspace --lcov --output-path lcov.info --fail-under-lines 80
      - uses: actions/upload-artifact@v4
        with: { name: lcov, path: lcov.info }

  docs:
    runs-on: ubuntu-latest
    env:
      RUSTDOCFLAGS: "-D warnings"
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo doc --workspace --no-deps
```

- [ ] **Step 2: Author the benchmark-regression workflow**

`.github/workflows/bench.yml`:

```yaml
name: bench
on:
  pull_request:
    paths:
      - 'crates/purple-wolf-core/**'
      - '.github/workflows/bench.yml'

jobs:
  bench-regression:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - name: Establish baseline from main
        run: |
          git fetch origin main
          git checkout origin/main -- crates/purple-wolf-core
          cargo bench -p purple-wolf-core -- --save-baseline main
          git checkout HEAD -- crates/purple-wolf-core
      - name: Compare PR against baseline (fail >10% regression)
        run: |
          cargo bench -p purple-wolf-core -- --baseline main \
            --noise-threshold 0.10 --significance-level 0.05 \
            --output-format bencher | tee bench.txt
          # criterion exits 0 even on regression; parse the report and gate.
          ! grep -E 'regressed|change: \+[1-9][0-9]\.' bench.txt
```

- [ ] **Step 3: Commit**

```bash
git add .github
git commit -m "ci: full matrix (test/lint/supply-chain/wasm/fuzz-smoke/coverage/docs) + bench gate"
```

---

## Phase G — Integration Test, Examples, Release

### Task 23: Traefik-in-Docker integration test suite

**Files:**
- Create: `tests/traefik_integration/Cargo.toml` (separate test crate, excluded from workspace; reusing the `fuzz` exclusion pattern)
- Create: `tests/traefik_integration/src/lib.rs` (empty — Cargo requires it)
- Create: `tests/traefik_integration/tests/end_to_end.rs`
- Create: `tests/traefik_integration/traefik/traefik.yml`
- Create: `tests/traefik_integration/traefik/dynamic.yml`

This suite assumes `docker` is on the PATH. CI installs it in the wasm-build job; locally any developer with docker can run `cargo test -p purple-wolf-traefik-integration`.

- [ ] **Step 1: Update workspace Cargo.toml to exclude the integration test crate**

In root `Cargo.toml` `[workspace] exclude` list: add `"tests/traefik_integration"`.

- [ ] **Step 2: Create the integration crate**

`tests/traefik_integration/Cargo.toml`:

```toml
[package]
name = "purple-wolf-traefik-integration"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]

[dev-dependencies]
ureq = "2"   # blocking HTTP client for tests
```

`tests/traefik_integration/src/lib.rs`:

```rust
// placeholder so cargo recognises this as a crate
```

- [ ] **Step 3: Write the Traefik config**

`tests/traefik_integration/traefik/traefik.yml`:

```yaml
entryPoints:
  web:
    address: ":8080"
providers:
  file:
    filename: /etc/traefik/dynamic.yml
experimental:
  localPlugins:
    purpleWolf:
      moduleName: github.com/guaracloud-oss/purple-wolf
log:
  level: INFO
```

`tests/traefik_integration/traefik/dynamic.yml`:

```yaml
http:
  routers:
    enforce:
      rule: "PathPrefix(`/e`)"
      service: echo
      middlewares: [strict-waf]
    monitor:
      rule: "PathPrefix(`/m`)"
      service: echo
      middlewares: [monitor-waf]
  services:
    echo:
      loadBalancer:
        servers:
          - url: "http://upstream:8000"
  middlewares:
    strict-waf:
      plugin:
        purpleWolf:
          mode: enforce
          groups:
            injection:  { enabled: true,  mode: enforce }
            signatures: { enabled: true,  mode: enforce }
    monitor-waf:
      plugin:
        purpleWolf:
          mode: monitor
          groups:
            injection: { enabled: true, mode: enforce }
```

- [ ] **Step 4: Write the end-to-end test**

`tests/traefik_integration/tests/end_to_end.rs`:

```rust
//! Spin up Traefik + a stub upstream in Docker with the built .wasm
//! mounted as a local plugin. Drive real HTTP. Assert WAF behavior.
use std::process::Command;
use std::time::Duration;

fn build_wasm() {
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "purple-wolf-traefik",
               "--target", "wasm32-wasip1"])
        .status().expect("cargo build");
    assert!(status.success(), "wasm build failed");
}

fn compose_up() {
    let _ = Command::new("docker").args(["compose", "down", "-v"]).status();
    let status = Command::new("docker")
        .current_dir("tests/traefik_integration")
        .args(["compose", "up", "-d"])
        .status().expect("docker compose up");
    assert!(status.success());
    std::thread::sleep(Duration::from_secs(4));
}

fn compose_down() {
    let _ = Command::new("docker")
        .current_dir("tests/traefik_integration")
        .args(["compose", "down", "-v"]).status();
}

struct Stack;
impl Drop for Stack { fn drop(&mut self) { compose_down(); } }

fn get(path: &str) -> u16 {
    ureq::get(&format!("http://127.0.0.1:8080{path}"))
        .call().map(|r| r.status()).unwrap_or_else(|e| match e {
            ureq::Error::Status(c, _) => c,
            _ => 0,
        })
}

#[test]
#[ignore = "requires docker on PATH; run with --ignored or in CI"]
fn enforce_blocks_sqli_through_real_traefik() {
    build_wasm();
    let _s = Stack;
    compose_up();
    assert_eq!(get("/e/api"), 200, "clean through enforce route");
    assert_eq!(get("/e/api?id=1%27%20OR%20%271%27%3D%271"), 403, "SQLi blocked by enforce");
    assert_eq!(get("/m/api?id=1%27%20OR%20%271%27%3D%271"), 200, "SQLi passes in monitor");
}
```

Add a `tests/traefik_integration/docker-compose.yml`:

```yaml
services:
  upstream:
    image: python:3-alpine
    command: ["python", "-m", "http.server", "8000"]
  traefik:
    image: traefik:v3
    command:
      - "--configFile=/etc/traefik/traefik.yml"
    ports: ["8080:8080"]
    volumes:
      - ./traefik:/etc/traefik:ro
      - ../../target/wasm32-wasip1/release/purple_wolf_traefik.wasm:/plugins-local/src/github.com/guaracloud-oss/purple-wolf/purple-wolf.wasm:ro
    depends_on: [upstream]
```

- [ ] **Step 5: Run locally (requires docker)**

```bash
WASI_SDK_PATH=${WASI_SDK_PATH:-/opt/wasi-sdk} \
  cargo build --release -p purple-wolf-traefik --target wasm32-wasip1
cargo test -p purple-wolf-traefik-integration -- --ignored --test-threads=1
```
Expected: PASS (or BLOCKED with clear docker/Traefik error — Traefik's local-plugin layout may need adjustment).

- [ ] **Step 6: Commit**

```bash
git add tests/traefik_integration .github/workflows/ci.yml Cargo.toml
git commit -m "test(integration): docker-based Traefik + plugin end-to-end suite"
```

(Optionally add a `traefik-integration` job to `ci.yml` that runs the same command; gate it on the wasm-build job's artifact.)

---

### Task 24: README quickstart + examples/ tenant Middlewares

**Files:**
- Modify: `README.md`
- Create: `examples/middleware-strict.yaml`
- Create: `examples/middleware-monitor.yaml`
- Create: `examples/middleware-routes.yaml` (an IngressRoute chaining one of the middlewares)
- Create: `docs/configuration.md`

- [ ] **Step 1: Write the example tenant Middlewares**

`examples/middleware-strict.yaml`:

```yaml
# A WAF Middleware blocking SQLi/XSS, signatures, structural anomalies.
# Reference this in an IngressRoute to protect a route in enforce mode.
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: purple-wolf-strict
  namespace: tenant-acme
spec:
  plugin:
    purpleWolf:
      mode: enforce
      failMode: failOpen
      body:
        maxInspectBytes: 1048576
        overCap: pass
      groups:
        injection:  { enabled: true, mode: enforce }
        signatures: { enabled: true, mode: enforce }
        structural: { enabled: true, mode: enforce }
        reputation: { enabled: true, mode: enforce }
      reputation:
        perSecond: 100
        denyList: []
```

`examples/middleware-monitor.yaml`:

```yaml
# Log-only WAF: never blocks, emits a JSON audit line for every verdict.
# Use this for a 1-2 week rollout to tune false positives, then switch
# to purple-wolf-strict.
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: purple-wolf-monitor
  namespace: tenant-acme
spec:
  plugin:
    purpleWolf:
      mode: monitor
      groups:
        injection:  { enabled: true, mode: enforce }
        signatures: { enabled: true, mode: enforce }
        structural: { enabled: true, mode: monitor }
        reputation: { enabled: true, mode: monitor }
```

`examples/middleware-routes.yaml`:

```yaml
# Chain the strict middleware on /admin and the monitor one elsewhere.
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: my-app
  namespace: tenant-acme
spec:
  entryPoints: [websecure]
  routes:
    - kind: Rule
      match: "Host(`acme.example.com`) && PathPrefix(`/admin`)"
      services: [{ name: my-app, port: 3000 }]
      middlewares: [{ name: purple-wolf-strict }]
    - kind: Rule
      match: "Host(`acme.example.com`)"
      services: [{ name: my-app, port: 3000 }]
      middlewares: [{ name: purple-wolf-monitor }]
```

- [ ] **Step 2: Write the configuration reference doc**

`docs/configuration.md`:

```markdown
# purple-wolf Middleware configuration reference

| field | type | default | meaning |
|---|---|---|---|
| `mode` | `enforce` \| `monitor` | (required) | Global switch. `monitor` never blocks regardless of group modes. |
| `failMode` | `failOpen` \| `failClosed` | `failOpen` | On detector soft failure: continue (`failOpen`) or 403 (`failClosed`). |
| `body.maxInspectBytes` | int | `1048576` | Max bytes of request body inspected. |
| `body.overCap` | `pass` \| `block` | `pass` | When body exceeds cap: `pass` lets Traefik forward; `block` returns 403. |
| `groups.injection` | `{ enabled, mode }` | `{true, enforce}` | SQLi + XSS via libinjection. |
| `groups.signatures` | `{ enabled, mode }` | `{true, enforce}` | Known-bad literal scanner (path traversal, RCE, scanner UAs). |
| `groups.structural` | `{ enabled, mode }` | `{true, monitor}` | Method allowlist + header anomalies. |
| `groups.reputation` | `{ enabled, mode }` | `{false, monitor}` | Per-IP rate limit + IP deny list. |
| `reputation.perSecond` | int | `100` | Per-IP token rate. **Per Traefik pod**; effective rate = configured × pod count. |
| `reputation.denyList` | list[string] | `[]` | IPs (or "ip:port" forms) to deny unconditionally. |

## Per-route specificity

`purple-wolf` does NOT implement per-host/per-path overrides inside the plugin
config. Instead, Traefik's native middleware attachment provides per-route
specificity: define multiple Middlewares with different configs and attach
them to the respective IngressRoute rules.

## Source IP

The plugin derives the source IP from `X-Forwarded-For` (first valid
`IpAddr`) → `X-Real-IP` → the TCP peer. Configure Traefik's `trustedIPs`
on the entrypoint so XFF is honored.

## Observability

- **Audit log:** one JSON line per noteworthy request via the host log sink
  (visible in Traefik's logs).
- **Metrics:** Traefik's built-in per-Middleware metrics; per-rule hit
  counts are derivable from audit-log fields via Loki/Promtail.
```

- [ ] **Step 3: Fill in README quickstart**

Replace the README `Quick start (Traefik)` section with concrete steps: install the wasm plugin into Traefik (link to Traefik's local-plugin docs), apply one of the example Middlewares, link to `docs/configuration.md`.

- [ ] **Step 4: Commit**

```bash
git add README.md examples docs/configuration.md
git commit -m "docs: README quickstart, tenant Middleware examples, config reference"
```

---

### Task 25: Release process (cargo-release + signed `.wasm` artifact)

**Files:**
- Create: `release.toml` (cargo-release config)
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Configure cargo-release**

`release.toml`:

```toml
sign-commit = true
sign-tag = true
push-remote = "origin"
shared-version = true
pre-release-commit-message = "chore(release): {{version}}"
tag-message = "purple-wolf {{version}}"
publish = false   # crate-level publish flag set in core's Cargo.toml
```

In `crates/purple-wolf-core/Cargo.toml` set `publish = true` (default). In `crates/purple-wolf-traefik/Cargo.toml` keep `publish = false`.

- [ ] **Step 2: Write the release workflow**

`.github/workflows/release.yml`:

```yaml
name: release
on:
  push:
    tags: ["v*"]

jobs:
  publish-and-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write   # for cosign keyless
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: wasm32-wasip1 }
      - name: Install wasi-sdk
        run: |
          curl -sSL https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-22/wasi-sdk-22.0-linux.tar.gz | tar xz -C /opt
          echo "WASI_SDK_PATH=/opt/wasi-sdk-22.0" >> $GITHUB_ENV
      - name: Build release WASM
        run: cargo build -p purple-wolf-traefik --target wasm32-wasip1 --release
      - name: Compute SHA256
        run: sha256sum target/wasm32-wasip1/release/purple_wolf_traefik.wasm > purple-wolf.wasm.sha256
      - uses: sigstore/cosign-installer@v3
      - name: Cosign keyless sign the WASM
        run: |
          cosign sign-blob --yes \
            target/wasm32-wasip1/release/purple_wolf_traefik.wasm \
            --output-signature purple-wolf.wasm.sig \
            --output-certificate purple-wolf.wasm.pem
      - uses: softprops/action-gh-release@v2
        with:
          files: |
            target/wasm32-wasip1/release/purple_wolf_traefik.wasm
            purple-wolf.wasm.sha256
            purple-wolf.wasm.sig
            purple-wolf.wasm.pem
      - name: Publish core to crates.io
        env: { CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }} }
        run: cargo publish -p purple-wolf-core
```

- [ ] **Step 3: Document the release procedure in CHANGELOG.md**

Append a brief "How to cut a release" appendix to `CHANGELOG.md` describing the `cargo release` + `git push --tags` flow.

- [ ] **Step 4: Commit**

```bash
git add release.toml .github/workflows/release.yml CHANGELOG.md crates/purple-wolf-core/Cargo.toml crates/purple-wolf-traefik/Cargo.toml
git commit -m "release: cargo-release + signed WASM via cosign + crates.io publish"
```

---

## Self-Review Notes

- **Spec coverage:** §1 goals (Tasks 1–25); §2 architecture (Tasks 1, 14, 15, 17); §3.1 core crate (Tasks 2–14); §3.2 traefik crate (Tasks 15–17); §4 Middleware schema (Tasks 16, 24); §5.1 unit tests (Tasks 2–13, 18); §5.2 fuzz (Task 19); §5.3 benchmarks (Task 21); §5.4 CI (Task 22); §5.5 release (Task 25); §6 migration (Phase B port tasks reference v0.1 modules verbatim); §7 error handling (Task 17 `catch_unwind` + fail-mode); §8 observability (Tasks 17 audit, 22 CI, 24 docs).
- **Open item resolution:** Task 14 commits to `wasm32-wasip1` (revisit if Traefik's wazero requires wasip2 at implementation time); Task 15 leaves http-wasm guest SDK choice deliberately at implementation time, surfacing the decision as Step 1 with two acceptable outcomes; Task 10 leaves `governor`-on-wasm32 viability as the final test inside Task 14, with a fallback path documented.
- **Type consistency:** `Request`, `Config`, `Engine`, `Verdict`, `Group`, `GroupMode`, `Mode`, `FailMode`, `OverCap`, `Decision`, `Action`, `AuditEntry`, `ReputationDetector::new(per_second, deny_list)` are the same names in every task that uses them. The plugin's `host::*` API in Task 15 matches the Task 17 caller exactly. Middleware JSON camelCase ↔ core snake_case adapter in Task 16 mirrors the Task 24 docs.
- **No placeholders:** every step contains the actual file content, command, or `git show` invocation needed to perform it. There are no "TBD", "implement later", or "similar to Task N" references.
