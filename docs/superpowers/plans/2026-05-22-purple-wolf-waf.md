# purple-wolf WAF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `purple-wolf`, a fast, low-memory Rust WAF that runs as a per-app-pod sidecar behind Traefik, inspecting full HTTP requests with a hybrid detection engine.

**Architecture:** A single async Rust binary. An axum server accepts plaintext HTTP from Traefik, buffers the body up to a configurable cap, builds a normalized request view, runs four toggleable detector groups (libinjection, aho-corasick signatures, structural checks, rate/IP reputation), and a policy layer turns verdicts into allow/block under a global mode and fail mode. Allowed requests are forwarded to the `localhost` app via reqwest. Config is a hot-reloaded TOML file.

**Tech Stack:** Rust, `tokio`, `axum` 0.7, `reqwest`, `libinjection` (vendored C via `cc`/FFI), `aho-corasick`, `governor`, `notify`, `arc-swap`, `serde`/`toml`, `metrics` + `metrics-exporter-prometheus`, `tracing`.

**Spec:** `docs/superpowers/specs/2026-05-22-purple-wolf-waf-design.md`

---

## File Structure

```
guaracloud-purple-wolf/
  Cargo.toml                       # deps + size-optimized release profile
  build.rs                         # compiles vendored libinjection C
  rust-toolchain.toml              # pins stable toolchain
  vendor/libinjection/             # vendored libinjection C sources + headers
  config/purple-wolf.toml          # default/example config
  src/
    main.rs                        # entrypoint: load config, start watcher + server
    config.rs                      # Config structs + TOML parsing
    request_model.rs               # RequestView: normalized, decoded request
    detectors/
      mod.rs                       # Group, Severity, Verdict, Detector trait, Engine
      injection.rs                 # libinjection-backed SQLi/XSS detector
      signatures.rs                # aho-corasick literal matcher
      structural.rs                # size/method/header anomaly checks
      reputation.rs                # rate limiting + IP allow/deny lists
    ffi.rs                         # extern "C" bindings for libinjection
    policy.rs                      # Decision: combine verdicts under mode + fail mode
    rules.rs                       # group-config resolution + ArcSwap hot-reload
    proxy.rs                       # axum handler: inspect -> block or forward
    observe.rs                     # Prometheus metrics + JSON audit log
  tests/
    integration.rs                 # full proxy: allow/block/monitor/fail modes
  deploy/
    Dockerfile                     # musl static build -> scratch image
    sidecar-example.yaml           # K8s Service + sidecar patch example
  docs/superpowers/...
```

Each `src` file has one responsibility. Detectors are pure functions over `RequestView` (except `reputation`, which holds rate-limiter state) so they test without a network.

---

## Task 1: Project scaffold & size-optimized build

**Files:**
- Create: `rust-toolchain.toml`, `Cargo.toml`, `src/main.rs`

- [ ] **Step 1: Verify the Rust toolchain**

Run: `cargo --version`
Expected: prints a version. If "command not found", install via `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y` then `source "$HOME/.cargo/env"`.

- [ ] **Step 2: Pin the toolchain**

Create `rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

- [ ] **Step 3: Create `Cargo.toml`**

```toml
[package]
name = "purple-wolf"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "purple-wolf"
path = "src/main.rs"

[dependencies]
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal", "net", "time"] }
axum = "0.7"
reqwest = { version = "0.12", default-features = false, features = ["stream"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"
aho-corasick = "1"
governor = "0.6"
notify = "6"
arc-swap = "1"
metrics = "0.23"
metrics-exporter-prometheus = { version = "0.15", default-features = false }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
percent-encoding = "2"
bytes = "1"

[dev-dependencies]
tokio = { version = "1", features = ["full"] }

[build-dependencies]
cc = "1"

# panic = "unwind" (default) is kept on purpose: the proxy uses catch_unwind
# for per-request panic isolation (spec section 8). Binary stays well under
# the size budget without panic = "abort".
[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
```

- [ ] **Step 4: Create a minimal `src/main.rs`**

```rust
fn main() {
    println!("purple-wolf starting");
}
```

- [ ] **Step 5: Build and verify**

Run: `cargo build --release`
Expected: compiles; binary at `target/release/purple-wolf`.

- [ ] **Step 6: Commit**

```bash
git add rust-toolchain.toml Cargo.toml src/main.rs
git commit -m "chore: scaffold purple-wolf cargo project"
```

---

## Task 2: Config model

**Files:**
- Create: `src/config.rs`, `config/purple-wolf.toml`
- Modify: `src/main.rs`
- Test: in `src/config.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing test**

Create `src/config.rs`:

```rust
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Monitor,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    FailOpen,
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupMode {
    Enforce,
    Monitor,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverCap {
    Pass,
    Block,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BodyConfig {
    pub max_inspect_bytes: usize,
    pub over_cap: OverCap,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_group_mode")]
    pub mode: GroupMode,
}

fn default_true() -> bool { true }
fn default_group_mode() -> GroupMode { GroupMode::Enforce }

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Groups {
    #[serde(default)]
    pub injection: Option<GroupConfig>,
    #[serde(default)]
    pub signatures: Option<GroupConfig>,
    #[serde(default)]
    pub structural: Option<GroupConfig>,
    #[serde(default)]
    pub reputation: Option<GroupConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Override {
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub disable_groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub mode: Mode,
    pub fail_mode: FailMode,
    pub body: BodyConfig,
    #[serde(default)]
    pub groups: Groups,
    #[serde(default)]
    pub overrides: Vec<Override>,
    pub upstream: String,
    pub listen: String,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let text = r#"
            mode = "monitor"
            fail_mode = "fail_open"
            upstream = "http://127.0.0.1:3000"
            listen = "0.0.0.0:8080"
            [body]
            max_inspect_bytes = 1048576
            over_cap = "pass"
            [groups.injection]
            enabled = true
            mode = "enforce"
            [[overrides]]
            host = "api.guaracloud.com"
            path_prefix = "/webhooks/"
            disable_groups = ["reputation"]
        "#;
        let cfg = Config::parse(text).expect("should parse");
        assert_eq!(cfg.mode, Mode::Monitor);
        assert_eq!(cfg.fail_mode, FailMode::FailOpen);
        assert_eq!(cfg.body.max_inspect_bytes, 1048576);
        assert_eq!(cfg.overrides.len(), 1);
        assert_eq!(cfg.overrides[0].disable_groups, vec!["reputation"]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test config::tests::parses_full_config`
Expected: FAIL — `config` module not declared in `main.rs`.

- [ ] **Step 3: Declare the module**

In `src/main.rs`, add at the top: `mod config;`

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test config::tests::parses_full_config`
Expected: PASS.

- [ ] **Step 5: Create the example config**

Create `config/purple-wolf.toml`:

```toml
mode = "monitor"
fail_mode = "fail_open"
upstream = "http://127.0.0.1:3000"
listen = "0.0.0.0:8080"

[body]
max_inspect_bytes = 1048576
over_cap = "pass"

[groups.injection]
enabled = true
mode = "enforce"

[groups.signatures]
enabled = true
mode = "enforce"

[groups.structural]
enabled = true
mode = "monitor"

[groups.reputation]
enabled = false
mode = "monitor"
```

- [ ] **Step 6: Commit**

```bash
git add src/config.rs src/main.rs config/purple-wolf.toml
git commit -m "feat: config model with TOML parsing"
```

---

## Task 3: Request model (normalization)

**Files:**
- Create: `src/request_model.rs`
- Modify: `src/main.rs`
- Test: in `src/request_model.rs`

- [ ] **Step 1: Write the failing test**

Create `src/request_model.rs`:

```rust
use percent_encoding::percent_decode_str;
use std::net::IpAddr;

/// A normalized, decoded view of one HTTP request. Detectors read this only.
#[derive(Debug, Clone)]
pub struct RequestView {
    pub method: String,
    pub host: String,
    pub path: String,
    /// Decoded query parameters: (name, value).
    pub query_params: Vec<(String, String)>,
    /// Header names are lowercased.
    pub headers: Vec<(String, String)>,
    pub header_bytes: usize,
    pub body: Vec<u8>,
    /// Lossy UTF-8 of the body, for text-based detectors.
    pub body_text: String,
    pub body_inspected: bool,
    pub source_ip: IpAddr,
}

impl RequestView {
    /// Build a view. `raw_query` is the part after `?` (may be empty).
    pub fn build(
        method: &str,
        host: &str,
        path: &str,
        raw_query: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        body_inspected: bool,
        source_ip: IpAddr,
    ) -> RequestView {
        let query_params = parse_query(raw_query);
        let header_bytes: usize = headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        let body_text = String::from_utf8_lossy(&body).into_owned();
        let headers = headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        RequestView {
            method: method.to_ascii_uppercase(),
            host: host.to_ascii_lowercase(),
            path: decode(path),
            query_params,
            headers,
            header_bytes,
            body,
            body_text,
            body_inspected,
            source_ip,
        }
    }

    /// Every string a detector should scan: path, param values, body text.
    pub fn inspectable_fields(&self) -> Vec<&str> {
        let mut out = vec![self.path.as_str()];
        for (_, v) in &self.query_params {
            out.push(v.as_str());
        }
        if self.body_inspected {
            out.push(self.body_text.as_str());
        }
        out
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Percent-decode once, lossily. Applied so encoded evasion payloads normalize.
fn decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn parse_query(raw: &str) -> Vec<(String, String)> {
    raw.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "1.2.3.4".parse().unwrap()
    }

    #[test]
    fn decodes_query_params() {
        let v = RequestView::build(
            "get", "Example.COM", "/search",
            "q=%27%20OR%201%3D1", vec![], vec![], false, ip(),
        );
        assert_eq!(v.method, "GET");
        assert_eq!(v.host, "example.com");
        assert_eq!(v.query_params, vec![("q".to_string(), "' OR 1=1".to_string())]);
    }

    #[test]
    fn inspectable_fields_skips_uninspected_body() {
        let v = RequestView::build(
            "POST", "h", "/p", "a=1",
            vec![], b"payload".to_vec(), false, ip(),
        );
        assert!(!v.inspectable_fields().contains(&"payload"));
        let v2 = RequestView::build(
            "POST", "h", "/p", "a=1",
            vec![], b"payload".to_vec(), true, ip(),
        );
        assert!(v2.inspectable_fields().contains(&"payload"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let v = RequestView::build(
            "GET", "h", "/", "",
            vec![("User-Agent".to_string(), "curl".to_string())],
            vec![], false, ip(),
        );
        assert_eq!(v.header("user-agent"), Some("curl"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test request_model::`
Expected: FAIL — module not declared.

- [ ] **Step 3: Declare the module**

In `src/main.rs`, add: `mod request_model;`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test request_model::`
Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/request_model.rs src/main.rs
git commit -m "feat: normalized request model"
```

---

## Task 4: Detector contract & engine

**Files:**
- Create: `src/detectors/mod.rs`
- Modify: `src/main.rs`
- Test: in `src/detectors/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `src/detectors/mod.rs`:

```rust
pub mod injection;
pub mod signatures;
pub mod structural;
pub mod reputation;

use crate::request_model::RequestView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Injection,
    Signatures,
    Structural,
    Reputation,
}

impl Group {
    pub fn as_str(&self) -> &'static str {
        match self {
            Group::Injection => "injection",
            Group::Signatures => "signatures",
            Group::Structural => "structural",
            Group::Reputation => "reputation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// One detection hit.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub group: Group,
    pub rule: &'static str,
    pub severity: Severity,
    pub detail: String,
}

/// A detector inspects a request and returns zero or more verdicts.
pub trait Detector: Send + Sync {
    fn group(&self) -> Group;
    fn inspect(&self, req: &RequestView) -> Vec<Verdict>;
}

/// Holds every detector and runs the enabled ones.
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Engine {
        Engine { detectors }
    }

    /// Run detectors whose group is in `enabled`. Returns all verdicts.
    pub fn inspect(&self, req: &RequestView, enabled: &[Group]) -> Vec<Verdict> {
        self.detectors
            .iter()
            .filter(|d| enabled.contains(&d.group()))
            .flat_map(|d| d.inspect(req))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_model::RequestView;
    use std::net::IpAddr;

    struct AlwaysHit(Group);
    impl Detector for AlwaysHit {
        fn group(&self) -> Group { self.0 }
        fn inspect(&self, _req: &RequestView) -> Vec<Verdict> {
            vec![Verdict {
                group: self.0,
                rule: "test",
                severity: Severity::High,
                detail: "hit".into(),
            }]
        }
    }

    fn req() -> RequestView {
        RequestView::build("GET", "h", "/", "", vec![], vec![], false,
            "1.2.3.4".parse::<IpAddr>().unwrap())
    }

    #[test]
    fn engine_runs_only_enabled_groups() {
        let engine = Engine::new(vec![
            Box::new(AlwaysHit(Group::Injection)),
            Box::new(AlwaysHit(Group::Structural)),
        ]);
        let verdicts = engine.inspect(&req(), &[Group::Injection]);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].group, Group::Injection);
    }
}
```

- [ ] **Step 2: Create empty detector module files**

So the `pub mod` lines compile, create stub files (filled by later tasks):

`src/detectors/injection.rs`, `src/detectors/signatures.rs`, `src/detectors/structural.rs`, `src/detectors/reputation.rs` — each containing only:

```rust
// implemented in a later task
```

- [ ] **Step 3: Declare the module**

In `src/main.rs`, add: `mod detectors;`

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test detectors::tests::engine_runs_only_enabled_groups`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/detectors/ src/main.rs
git commit -m "feat: detector trait and engine"
```

---

## Task 5: Vendor libinjection & FFI bindings

**Files:**
- Create: `vendor/libinjection/` (downloaded C sources), `build.rs`, `src/ffi.rs`
- Modify: `src/main.rs`
- Test: in `src/ffi.rs`

- [ ] **Step 1: Vendor the libinjection C sources**

Run:

```bash
mkdir -p vendor
git clone --depth 1 https://github.com/libinjection/libinjection.git /tmp/libinjection
mkdir -p vendor/libinjection
cp /tmp/libinjection/src/libinjection_sqli.c \
   /tmp/libinjection/src/libinjection_xss.c \
   /tmp/libinjection/src/libinjection_html5.c \
   /tmp/libinjection/src/libinjection_sqli_data.h \
   /tmp/libinjection/src/libinjection_html5.h \
   /tmp/libinjection/src/libinjection.h \
   /tmp/libinjection/COPYING \
   vendor/libinjection/
rm -rf /tmp/libinjection
ls vendor/libinjection
```

Expected: the six source/header files plus `COPYING` listed.

- [ ] **Step 2: Create `build.rs`**

```rust
fn main() {
    println!("cargo:rerun-if-changed=vendor/libinjection");
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

- [ ] **Step 3: Write the failing test**

Create `src/ffi.rs`:

```rust
//! FFI bindings for vendored libinjection. This is the only `unsafe` boundary.
use std::os::raw::{c_char, c_int};

extern "C" {
    /// Returns 1 if `input` looks like SQL injection. `fingerprint` must be a
    /// buffer of at least 8 bytes; libinjection writes the matched fingerprint.
    fn libinjection_sqli(input: *const c_char, slen: usize, fingerprint: *mut c_char) -> c_int;

    /// Returns 1 if `input` looks like cross-site scripting.
    fn libinjection_xss(input: *const c_char, slen: usize) -> c_int;
}

/// Safe wrapper: is `s` SQL injection?
pub fn is_sqli(s: &str) -> bool {
    let mut fp = [0i8; 16];
    // SAFETY: pointer + length describe `s`; fp is a valid 16-byte buffer.
    let r = unsafe { libinjection_sqli(s.as_ptr() as *const c_char, s.len(), fp.as_mut_ptr()) };
    r == 1
}

/// Safe wrapper: is `s` cross-site scripting?
pub fn is_xss(s: &str) -> bool {
    // SAFETY: pointer + length describe `s`.
    let r = unsafe { libinjection_xss(s.as_ptr() as *const c_char, s.len()) };
    r == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sqli() {
        assert!(is_sqli("1' OR '1'='1"));
        assert!(is_sqli("'; DROP TABLE users; --"));
    }

    #[test]
    fn detects_xss() {
        assert!(is_xss("<script>alert(1)</script>"));
    }

    #[test]
    fn passes_benign_input() {
        assert!(!is_sqli("hello world"));
        assert!(!is_xss("hello world"));
    }
}
```

- [ ] **Step 4: Declare the module**

In `src/main.rs`, add: `mod ffi;`

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test ffi::`
Expected: 3 tests PASS (build.rs compiles the C first).

- [ ] **Step 6: Commit**

```bash
git add vendor/ build.rs src/ffi.rs src/main.rs
git commit -m "feat: vendor libinjection and add safe FFI wrappers"
```

---

## Task 6: Injection detector

**Files:**
- Modify: `src/detectors/injection.rs`
- Test: in `src/detectors/injection.rs`

- [ ] **Step 1: Write the failing test (replace the stub)**

Replace `src/detectors/injection.rs` with:

```rust
use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::ffi;
use crate::request_model::RequestView;

/// SQLi/XSS detector backed by libinjection.
pub struct InjectionDetector;

impl Detector for InjectionDetector {
    fn group(&self) -> Group {
        Group::Injection
    }

    fn inspect(&self, req: &RequestView) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        for field in req.inspectable_fields() {
            if ffi::is_sqli(field) {
                verdicts.push(Verdict {
                    group: Group::Injection,
                    rule: "sqli",
                    severity: Severity::Critical,
                    detail: format!("SQLi in field: {}", truncate(field)),
                });
            }
            if ffi::is_xss(field) {
                verdicts.push(Verdict {
                    group: Group::Injection,
                    rule: "xss",
                    severity: Severity::High,
                    detail: format!("XSS in field: {}", truncate(field)),
                });
            }
        }
        verdicts
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn req_with_query(q: &str) -> RequestView {
        RequestView::build("GET", "h", "/s", q, vec![], vec![], false,
            "1.2.3.4".parse::<IpAddr>().unwrap())
    }

    #[test]
    fn flags_sqli_in_query() {
        let v = InjectionDetector.inspect(&req_with_query("id=1%27%20OR%20%271%27%3D%271"));
        assert!(v.iter().any(|x| x.rule == "sqli"));
    }

    #[test]
    fn flags_xss_in_query() {
        let v = InjectionDetector.inspect(&req_with_query("c=%3Cscript%3Ealert(1)%3C/script%3E"));
        assert!(v.iter().any(|x| x.rule == "xss"));
    }

    #[test]
    fn benign_query_is_clean() {
        let v = InjectionDetector.inspect(&req_with_query("name=victor&page=2"));
        assert!(v.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail then pass**

Run: `cargo test detectors::injection::`
Expected: PASS (compiles against Task 4 + 5 code; if run before those, FAIL).

- [ ] **Step 3: Commit**

```bash
git add src/detectors/injection.rs
git commit -m "feat: libinjection-backed SQLi/XSS detector"
```

---

## Task 7: Signature detector (aho-corasick)

**Files:**
- Modify: `src/detectors/signatures.rs`
- Test: in `src/detectors/signatures.rs`

- [ ] **Step 1: Write the failing test (replace the stub)**

Replace `src/detectors/signatures.rs` with:

```rust
use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request_model::RequestView;
use aho_corasick::AhoCorasick;

/// (literal, rule name, severity) — extend this table to add signatures.
const SIGNATURES: &[(&str, &str, Severity)] = &[
    ("../", "path_traversal", Severity::High),
    ("..\\", "path_traversal", Severity::High),
    ("/etc/passwd", "lfi", Severity::Critical),
    ("$(", "rce_subshell", Severity::Critical),
    ("`", "rce_backtick", Severity::High),
    ("/bin/sh", "rce_shell", Severity::Critical),
    ("sqlmap", "scanner_ua", Severity::Medium),
    ("nikto", "scanner_ua", Severity::Medium),
    ("nuclei", "scanner_ua", Severity::Medium),
];

/// Matches all known-bad literals in a single pass.
pub struct SignatureDetector {
    matcher: AhoCorasick,
}

impl SignatureDetector {
    pub fn new() -> SignatureDetector {
        let patterns: Vec<&str> = SIGNATURES.iter().map(|(p, _, _)| *p).collect();
        let matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("static signature set must build");
        SignatureDetector { matcher }
    }
}

impl Detector for SignatureDetector {
    fn group(&self) -> Group {
        Group::Signatures
    }

    fn inspect(&self, req: &RequestView) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        // Scan path/params/body plus the User-Agent header.
        let mut fields = req.inspectable_fields();
        if let Some(ua) = req.header("user-agent") {
            fields.push(ua);
        }
        for field in fields {
            for m in self.matcher.find_iter(field) {
                let (lit, rule, sev) = SIGNATURES[m.pattern().as_usize()];
                verdicts.push(Verdict {
                    group: Group::Signatures,
                    rule,
                    severity: sev,
                    detail: format!("matched signature `{}`", lit),
                });
            }
        }
        verdicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip() -> IpAddr { "1.2.3.4".parse().unwrap() }

    #[test]
    fn flags_path_traversal() {
        let req = RequestView::build("GET", "h", "/files", "f=../../etc/passwd",
            vec![], vec![], false, ip());
        let v = SignatureDetector::new().inspect(&req);
        assert!(v.iter().any(|x| x.rule == "path_traversal" || x.rule == "lfi"));
    }

    #[test]
    fn flags_scanner_user_agent() {
        let req = RequestView::build("GET", "h", "/", "",
            vec![("user-agent".into(), "sqlmap/1.7".into())], vec![], false, ip());
        let v = SignatureDetector::new().inspect(&req);
        assert!(v.iter().any(|x| x.rule == "scanner_ua"));
    }

    #[test]
    fn benign_request_is_clean() {
        let req = RequestView::build("GET", "h", "/about", "ref=home",
            vec![("user-agent".into(), "Mozilla/5.0".into())], vec![], false, ip());
        assert!(SignatureDetector::new().inspect(&req).is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test detectors::signatures::`
Expected: 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/detectors/signatures.rs
git commit -m "feat: aho-corasick signature detector"
```

---

## Task 8: Structural detector

**Files:**
- Modify: `src/detectors/structural.rs`
- Test: in `src/detectors/structural.rs`

- [ ] **Step 1: Write the failing test (replace the stub)**

Replace `src/detectors/structural.rs` with:

```rust
use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request_model::RequestView;

const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_COUNT: usize = 100;

/// Plain-logic anomaly checks: method allowlist, header size/count limits.
pub struct StructuralDetector;

impl Detector for StructuralDetector {
    fn group(&self) -> Group {
        Group::Structural
    }

    fn inspect(&self, req: &RequestView) -> Vec<Verdict> {
        let mut verdicts = Vec::new();

        if !ALLOWED_METHODS.contains(&req.method.as_str()) {
            verdicts.push(Verdict {
                group: Group::Structural,
                rule: "method_not_allowed",
                severity: Severity::Medium,
                detail: format!("method `{}` not in allowlist", req.method),
            });
        }
        if req.header_bytes > MAX_HEADER_BYTES {
            verdicts.push(Verdict {
                group: Group::Structural,
                rule: "headers_too_large",
                severity: Severity::Medium,
                detail: format!("{} header bytes exceeds {}", req.header_bytes, MAX_HEADER_BYTES),
            });
        }
        if req.headers.len() > MAX_HEADER_COUNT {
            verdicts.push(Verdict {
                group: Group::Structural,
                rule: "too_many_headers",
                severity: Severity::Medium,
                detail: format!("{} headers exceeds {}", req.headers.len(), MAX_HEADER_COUNT),
            });
        }
        verdicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip() -> IpAddr { "1.2.3.4".parse().unwrap() }

    #[test]
    fn flags_disallowed_method() {
        let req = RequestView::build("TRACE", "h", "/", "", vec![], vec![], false, ip());
        let v = StructuralDetector.inspect(&req);
        assert!(v.iter().any(|x| x.rule == "method_not_allowed"));
    }

    #[test]
    fn flags_too_many_headers() {
        let headers: Vec<(String, String)> =
            (0..150).map(|i| (format!("x-{i}"), "v".into())).collect();
        let req = RequestView::build("GET", "h", "/", "", headers, vec![], false, ip());
        let v = StructuralDetector.inspect(&req);
        assert!(v.iter().any(|x| x.rule == "too_many_headers"));
    }

    #[test]
    fn normal_request_is_clean() {
        let req = RequestView::build("GET", "h", "/", "",
            vec![("accept".into(), "*/*".into())], vec![], false, ip());
        assert!(StructuralDetector.inspect(&req).is_empty());
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test detectors::structural::`
Expected: 3 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/detectors/structural.rs
git commit -m "feat: structural anomaly detector"
```

---

## Task 9: Reputation detector (rate limiting + IP lists)

**Files:**
- Modify: `src/detectors/reputation.rs`
- Test: in `src/detectors/reputation.rs`

- [ ] **Step 1: Write the failing test (replace the stub)**

Replace `src/detectors/reputation.rs` with:

```rust
use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request_model::RequestView;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;

type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Per-instance rate limiting plus static IP allow/deny lists.
pub struct ReputationDetector {
    limiter: IpLimiter,
    deny_list: Vec<IpAddr>,
}

impl ReputationDetector {
    /// `per_second` requests allowed per source IP before flagging.
    pub fn new(per_second: u32, deny_list: Vec<IpAddr>) -> ReputationDetector {
        let quota = Quota::per_second(NonZeroU32::new(per_second.max(1)).unwrap());
        ReputationDetector {
            limiter: RateLimiter::keyed(quota),
            deny_list,
        }
    }
}

impl Detector for ReputationDetector {
    fn group(&self) -> Group {
        Group::Reputation
    }

    fn inspect(&self, req: &RequestView) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        if self.deny_list.contains(&req.source_ip) {
            verdicts.push(Verdict {
                group: Group::Reputation,
                rule: "ip_denied",
                severity: Severity::High,
                detail: format!("source IP {} on deny list", req.source_ip),
            });
        }
        if self.limiter.check_key(&req.source_ip).is_err() {
            verdicts.push(Verdict {
                group: Group::Reputation,
                rule: "rate_limited",
                severity: Severity::Medium,
                detail: format!("source IP {} exceeded rate quota", req.source_ip),
            });
        }
        verdicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_from(ip: &str) -> RequestView {
        RequestView::build("GET", "h", "/", "", vec![], vec![], false, ip.parse().unwrap())
    }

    #[test]
    fn flags_denied_ip() {
        let det = ReputationDetector::new(1000, vec!["9.9.9.9".parse().unwrap()]);
        let v = det.inspect(&req_from("9.9.9.9"));
        assert!(v.iter().any(|x| x.rule == "ip_denied"));
    }

    #[test]
    fn rate_limits_burst_from_one_ip() {
        let det = ReputationDetector::new(1, vec![]);
        let mut limited = false;
        for _ in 0..50 {
            if det.inspect(&req_from("5.5.5.5")).iter().any(|x| x.rule == "rate_limited") {
                limited = true;
            }
        }
        assert!(limited, "burst should trip the rate limiter");
    }
}
```

- [ ] **Step 2: Run tests**

Run: `cargo test detectors::reputation::`
Expected: 2 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/detectors/reputation.rs
git commit -m "feat: reputation detector with rate limiting and IP lists"
```

---

## Task 10: Policy layer

**Files:**
- Create: `src/policy.rs`
- Modify: `src/main.rs`
- Test: in `src/policy.rs`

- [ ] **Step 1: Write the failing test**

Create `src/policy.rs`:

```rust
use crate::config::{GroupMode, Mode};
use crate::detectors::{Group, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Block,
}

/// The final decision for one request.
#[derive(Debug)]
pub struct Decision {
    pub action: Action,
    /// The verdict that caused a block, if any.
    pub blocked_by: Option<Verdict>,
    /// Verdicts seen but not enforced (monitor mode) — for audit logging.
    pub would_block: Vec<Verdict>,
}

/// Resolve verdicts into an action.
///
/// `global` is the global mode. `group_mode` maps a group to its effective
/// mode (already resolved against per-host/path overrides by `rules.rs`).
/// A verdict blocks only when BOTH the global mode and the group mode enforce.
pub fn decide(
    verdicts: Vec<Verdict>,
    global: Mode,
    group_mode: impl Fn(Group) -> GroupMode,
) -> Decision {
    let mut blocked_by = None;
    let mut would_block = Vec::new();

    for v in verdicts {
        let gm = group_mode(v.group);
        if gm == GroupMode::Off {
            continue;
        }
        let enforced = global == Mode::Enforce && gm == GroupMode::Enforce;
        if enforced && blocked_by.is_none() {
            blocked_by = Some(v);
        } else {
            would_block.push(v);
        }
    }

    Decision {
        action: if blocked_by.is_some() { Action::Block } else { Action::Allow },
        blocked_by,
        would_block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::Severity;

    fn verdict(group: Group) -> Verdict {
        Verdict { group, rule: "t", severity: Severity::High, detail: "d".into() }
    }

    #[test]
    fn blocks_when_global_and_group_enforce() {
        let d = decide(vec![verdict(Group::Injection)], Mode::Enforce, |_| GroupMode::Enforce);
        assert_eq!(d.action, Action::Block);
        assert!(d.blocked_by.is_some());
    }

    #[test]
    fn monitor_global_never_blocks() {
        let d = decide(vec![verdict(Group::Injection)], Mode::Monitor, |_| GroupMode::Enforce);
        assert_eq!(d.action, Action::Allow);
        assert_eq!(d.would_block.len(), 1);
    }

    #[test]
    fn group_mode_off_is_ignored() {
        let d = decide(vec![verdict(Group::Injection)], Mode::Enforce, |_| GroupMode::Off);
        assert_eq!(d.action, Action::Allow);
        assert!(d.would_block.is_empty());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test policy::`
Expected: FAIL — module not declared.

- [ ] **Step 3: Declare the module**

In `src/main.rs`, add: `mod policy;`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test policy::`
Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/policy.rs src/main.rs
git commit -m "feat: policy layer resolving verdicts to actions"
```

---

## Task 11: Rules — group-mode resolution & hot-reload

**Files:**
- Create: `src/rules.rs`
- Modify: `src/main.rs`
- Test: in `src/rules.rs`

- [ ] **Step 1: Write the failing test**

Create `src/rules.rs`:

```rust
use crate::config::{Config, GroupConfig, GroupMode};
use crate::detectors::Group;
use arc_swap::ArcSwap;
use std::path::PathBuf;
use std::sync::Arc;

/// Thread-safe holder of the live config, swappable on hot-reload.
pub struct Rules {
    config: ArcSwap<Config>,
    path: PathBuf,
}

impl Rules {
    pub fn new(config: Config, path: PathBuf) -> Rules {
        Rules { config: ArcSwap::from_pointee(config), path }
    }

    pub fn current(&self) -> Arc<Config> {
        self.config.load_full()
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Re-read the config file. On parse error, keep the existing config.
    pub fn reload(&self) -> Result<(), String> {
        let text = std::fs::read_to_string(&self.path).map_err(|e| e.to_string())?;
        let cfg = Config::parse(&text).map_err(|e| e.to_string())?;
        self.config.store(Arc::new(cfg));
        Ok(())
    }

    /// Effective mode for `group` given request `host`/`path`, applying the
    /// group's own config and any matching override (override wins -> Off).
    pub fn group_mode(&self, cfg: &Config, group: Group, host: &str, path: &str) -> GroupMode {
        for ov in &cfg.overrides {
            let host_ok = ov.host.as_deref().map_or(true, |h| h == host);
            let path_ok = ov.path_prefix.as_deref().map_or(true, |p| path.starts_with(p));
            if host_ok && path_ok && ov.disable_groups.iter().any(|g| g == group.as_str()) {
                return GroupMode::Off;
            }
        }
        let gc: Option<&GroupConfig> = match group {
            Group::Injection => cfg.groups.injection.as_ref(),
            Group::Signatures => cfg.groups.signatures.as_ref(),
            Group::Structural => cfg.groups.structural.as_ref(),
            Group::Reputation => cfg.groups.reputation.as_ref(),
        };
        match gc {
            Some(g) if g.enabled => g.mode,
            _ => GroupMode::Off,
        }
    }

    /// Groups whose effective mode is not Off — the set to actually run.
    pub fn enabled_groups(&self, cfg: &Config, host: &str, path: &str) -> Vec<Group> {
        [Group::Injection, Group::Signatures, Group::Structural, Group::Reputation]
            .into_iter()
            .filter(|g| self.group_mode(cfg, *g, host, path) != GroupMode::Off)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        Config::parse(text).unwrap()
    }

    const BASE: &str = r#"
        mode = "enforce"
        fail_mode = "fail_open"
        upstream = "http://127.0.0.1:3000"
        listen = "0.0.0.0:8080"
        [body]
        max_inspect_bytes = 1024
        over_cap = "pass"
        [groups.injection]
        enabled = true
        mode = "enforce"
        [groups.reputation]
        enabled = false
        mode = "monitor"
    "#;

    #[test]
    fn disabled_group_resolves_to_off() {
        let cfg = config(BASE);
        let rules = Rules::new(cfg.clone(), "x.toml".into());
        assert_eq!(rules.group_mode(&cfg, Group::Reputation, "h", "/"), GroupMode::Off);
        assert_eq!(rules.group_mode(&cfg, Group::Injection, "h", "/"), GroupMode::Enforce);
    }

    #[test]
    fn override_disables_group_for_matching_path() {
        let text = format!("{BASE}\n[[overrides]]\nhost = \"api.x\"\npath_prefix = \"/hooks/\"\ndisable_groups = [\"injection\"]");
        let cfg = config(&text);
        let rules = Rules::new(cfg.clone(), "x.toml".into());
        assert_eq!(rules.group_mode(&cfg, Group::Injection, "api.x", "/hooks/stripe"), GroupMode::Off);
        assert_eq!(rules.group_mode(&cfg, Group::Injection, "api.x", "/other"), GroupMode::Enforce);
    }

    #[test]
    fn enabled_groups_excludes_off() {
        let cfg = config(BASE);
        let rules = Rules::new(cfg.clone(), "x.toml".into());
        let groups = rules.enabled_groups(&cfg, "h", "/");
        assert!(groups.contains(&Group::Injection));
        assert!(!groups.contains(&Group::Reputation));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test rules::`
Expected: FAIL — module not declared.

- [ ] **Step 3: Declare the module**

In `src/main.rs`, add: `mod rules;`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test rules::`
Expected: 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/rules.rs src/main.rs
git commit -m "feat: rule-group resolution with per-host/path overrides"
```

---

## Task 12: Observability — metrics & audit log

**Files:**
- Create: `src/observe.rs`
- Modify: `src/main.rs`
- Test: in `src/observe.rs`

- [ ] **Step 1: Write the failing test**

Create `src/observe.rs`:

```rust
use crate::policy::{Action, Decision};
use crate::request_model::RequestView;
use serde::Serialize;

/// One audit-log line. Emitted for any request with verdicts.
#[derive(Debug, Serialize, PartialEq)]
pub struct AuditEntry {
    pub host: String,
    pub path: String,
    pub method: String,
    pub source_ip: String,
    pub action: String,
    pub blocked_rule: Option<String>,
    pub would_block_rules: Vec<String>,
}

impl AuditEntry {
    pub fn from(req: &RequestView, decision: &Decision) -> AuditEntry {
        AuditEntry {
            host: req.host.clone(),
            path: req.path.clone(),
            method: req.method.clone(),
            source_ip: req.source_ip.to_string(),
            action: match decision.action {
                Action::Allow => "allow",
                Action::Block => "block",
            }
            .to_string(),
            blocked_rule: decision.blocked_by.as_ref().map(|v| {
                format!("{}/{}", v.group.as_str(), v.rule)
            }),
            would_block_rules: decision
                .would_block
                .iter()
                .map(|v| format!("{}/{}", v.group.as_str(), v.rule))
                .collect(),
        }
    }

    /// True if there is anything worth logging.
    pub fn is_noteworthy(&self) -> bool {
        self.blocked_rule.is_some() || !self.would_block_rules.is_empty()
    }
}

/// Record Prometheus counters/histogram for one handled request.
pub fn record_request(action: Action, group_hits: &[&str], latency_us: f64) {
    metrics::counter!("purple_wolf_requests_total").increment(1);
    match action {
        Action::Allow => metrics::counter!("purple_wolf_allowed_total").increment(1),
        Action::Block => metrics::counter!("purple_wolf_blocked_total").increment(1),
    }
    for g in group_hits {
        metrics::counter!("purple_wolf_group_hits_total", "group" => g.to_string()).increment(1);
    }
    metrics::histogram!("purple_wolf_added_latency_us").record(latency_us);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::{Group, Severity, Verdict};
    use std::net::IpAddr;

    fn req() -> RequestView {
        RequestView::build("GET", "Host", "/p", "", vec![], vec![], false,
            "1.2.3.4".parse::<IpAddr>().unwrap())
    }

    #[test]
    fn audit_entry_records_block() {
        let decision = Decision {
            action: Action::Block,
            blocked_by: Some(Verdict {
                group: Group::Injection, rule: "sqli",
                severity: Severity::Critical, detail: "d".into(),
            }),
            would_block: vec![],
        };
        let entry = AuditEntry::from(&req(), &decision);
        assert_eq!(entry.action, "block");
        assert_eq!(entry.blocked_rule.as_deref(), Some("injection/sqli"));
        assert!(entry.is_noteworthy());
    }

    #[test]
    fn clean_request_is_not_noteworthy() {
        let decision = Decision { action: Action::Allow, blocked_by: None, would_block: vec![] };
        assert!(!AuditEntry::from(&req(), &decision).is_noteworthy());
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test observe::`
Expected: FAIL — module not declared.

- [ ] **Step 3: Declare the module**

In `src/main.rs`, add: `mod observe;`

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test observe::`
Expected: 2 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/observe.rs src/main.rs
git commit -m "feat: audit log entries and Prometheus metrics"
```

---

## Task 13: Proxy handler

**Files:**
- Create: `src/proxy.rs`
- Modify: `src/main.rs`
- Test: covered by Task 15 integration tests (handler needs a running server)

- [ ] **Step 1: Create `src/proxy.rs`**

```rust
use crate::config::{Config, FailMode, OverCap};
use crate::detectors::{Engine, Group};
use crate::observe::{self, AuditEntry};
use crate::policy::{self, Action, Decision};
use crate::request_model::RequestView;
use crate::rules::Rules;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Shared state handed to every request.
#[derive(Clone)]
pub struct AppState {
    pub rules: Arc<Rules>,
    pub engine: Arc<Engine>,
    pub http: reqwest::Client,
}

/// Axum handler: inspect the request, then block or forward to the upstream.
pub async fn handle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let cfg = state.rules.current();

    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let raw_query = parts.uri.query().unwrap_or("").to_string();
    let method = parts.method.as_str().to_string();
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Buffer the body up to the inspection cap.
    let (body_bytes, body_inspected) = read_body(body, cfg.body.max_inspect_bytes).await;
    if body_bytes.is_none() && cfg.body.over_cap == OverCap::Block {
        return blocked_response("body exceeds inspection cap");
    }
    let raw_body = body_bytes.clone().unwrap_or_default();

    let view = RequestView::build(
        &method, &host, &path, &raw_query, headers.clone(),
        raw_body.to_vec(), body_inspected, peer.ip(),
    );

    // Inspect, isolating any detector panic per request.
    let enabled = state.rules.enabled_groups(&cfg, &view.host, &view.path);
    let inspect = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.engine.inspect(&view, &enabled)
    }));

    let decision = match inspect {
        Ok(verdicts) => {
            let rules = state.rules.clone();
            let cfg2 = cfg.clone();
            let host = view.host.clone();
            let path = view.path.clone();
            policy::decide(verdicts, cfg.mode, move |g: Group| {
                rules.group_mode(&cfg2, g, &host, &path)
            })
        }
        Err(_) => {
            // Soft failure: apply fail mode.
            metrics::counter!("purple_wolf_soft_failures_total").increment(1);
            match cfg.fail_mode {
                FailMode::FailClosed => {
                    return blocked_response("inspection failed (fail_closed)")
                }
                FailMode::FailOpen => Decision {
                    action: Action::Allow, blocked_by: None, would_block: vec![],
                },
            }
        }
    };

    // Audit log + metrics.
    let entry = AuditEntry::from(&view, &decision);
    if entry.is_noteworthy() {
        tracing::warn!(target: "audit", entry = %serde_json::to_string(&entry).unwrap_or_default());
    }
    let hits: Vec<&str> = decision
        .would_block
        .iter()
        .chain(decision.blocked_by.iter())
        .map(|v| v.group.as_str())
        .collect();
    observe::record_request(decision.action, &hits, started.elapsed().as_micros() as f64);

    match decision.action {
        Action::Block => blocked_response("request blocked by purple-wolf"),
        Action::Allow => forward(&state.http, &cfg, &parts, raw_body).await,
    }
}

/// Read the body, capped. Returns (Some(bytes), true) if fully read within the
/// cap, or (None, false) if it exceeded the cap.
async fn read_body(body: Body, cap: usize) -> (Option<Bytes>, bool) {
    match axum::body::to_bytes(body, cap).await {
        Ok(b) => (Some(b), true),
        Err(_) => (None, false),
    }
}

/// Forward an allowed request to the configured `localhost` upstream.
async fn forward(
    client: &reqwest::Client,
    cfg: &Config,
    parts: &axum::http::request::Parts,
    body: Bytes,
) -> Response<Body> {
    let url = format!(
        "{}{}",
        cfg.upstream.trim_end_matches('/'),
        parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    );
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(method, &url).body(body);
    for (k, v) in parts.headers.iter() {
        if k.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_bytes());
    }
    match builder.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let bytes = resp.bytes().await.unwrap_or_default();
            let mut out = Response::new(Body::from(bytes));
            *out.status_mut() = status;
            out
        }
        Err(_) => {
            let mut out = Response::new(Body::from("upstream unreachable"));
            *out.status_mut() = StatusCode::BAD_GATEWAY;
            out
        }
    }
}

fn blocked_response(reason: &str) -> Response<Body> {
    let mut out = Response::new(Body::from(reason.to_string()));
    *out.status_mut() = StatusCode::FORBIDDEN;
    out
}
```

- [ ] **Step 2: Declare the module**

In `src/main.rs`, add: `mod proxy;`. Add `serde_json = "1"` to `[dependencies]` in `Cargo.toml` (used for the audit log line).

- [ ] **Step 3: Verify it compiles**

Run: `cargo build`
Expected: compiles with no errors (warnings about unused `main` code are fine until Task 14).

- [ ] **Step 4: Commit**

```bash
git add src/proxy.rs src/main.rs Cargo.toml
git commit -m "feat: proxy handler with inspect, block, and forward"
```

---

## Task 14: Wire up `main.rs`

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Replace `src/main.rs` body**

Keep the existing `mod` lines at the top, then replace `fn main` with:

```rust
mod config;
mod detectors;
mod ffi;
mod observe;
mod policy;
mod proxy;
mod request_model;
mod rules;

use crate::config::Config;
use crate::detectors::injection::InjectionDetector;
use crate::detectors::reputation::ReputationDetector;
use crate::detectors::signatures::SignatureDetector;
use crate::detectors::structural::StructuralDetector;
use crate::detectors::{Detector, Engine};
use crate::proxy::AppState;
use crate::rules::Rules;
use axum::routing::any;
use axum::Router;
use notify::{RecursiveMode, Watcher};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()),
    ).init();

    let config_path = PathBuf::from(
        std::env::var("PURPLE_WOLF_CONFIG").unwrap_or_else(|_| "config/purple-wolf.toml".into()),
    );
    let text = std::fs::read_to_string(&config_path).expect("config file must exist");
    let cfg: Config = Config::parse(&text).expect("config must parse");
    let listen: SocketAddr = cfg.listen.parse().expect("listen must be a socket addr");

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(InjectionDetector),
        Box::new(SignatureDetector::new()),
        Box::new(StructuralDetector),
        Box::new(ReputationDetector::new(100, vec![])),
    ];
    let rules = Arc::new(Rules::new(cfg, config_path.clone()));

    // Hot-reload watcher: re-read config on file change.
    let watch_rules = rules.clone();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            match watch_rules.reload() {
                Ok(()) => tracing::info!("config reloaded"),
                Err(e) => tracing::error!(error = %e, "config reload failed; keeping previous"),
            }
        }
    })
    .expect("watcher must build");
    watcher
        .watch(&config_path, RecursiveMode::NonRecursive)
        .expect("must watch config file");

    let state = AppState {
        rules,
        engine: Arc::new(Engine::new(detectors)),
        http: reqwest::Client::new(),
    };

    // Prometheus metrics on a second listener.
    let prom = metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], 9090))
        .install()
        .expect("metrics exporter must install");
    drop(prom);

    let app = Router::new()
        .fallback(any(proxy::handle))
        .with_state(state);

    tracing::info!(%listen, "purple-wolf listening");
    let listener = tokio::net::TcpListener::bind(listen).await.expect("bind");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server");
}
```

Delete the old `mod` lines you added in earlier tasks if they now appear twice — the block above is the single source of truth for module declarations.

- [ ] **Step 2: Build and run**

Run: `cargo build --release`
Expected: compiles cleanly.

- [ ] **Step 3: Smoke test against a dummy upstream**

Run:

```bash
python3 -m http.server 3000 &
PURPLE_WOLF_CONFIG=config/purple-wolf.toml ./target/release/purple-wolf &
sleep 1
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8080/"
curl -s -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8080/?id=1%27%20OR%20%271%27%3D%271"
kill %1 %2
```

Expected: first curl prints `200` (forwarded); with `mode = "monitor"` the SQLi curl also prints `200` but logs an audit line. (Switch `mode` to `enforce` to see `403`.)

- [ ] **Step 4: Commit**

```bash
git add src/main.rs
git commit -m "feat: wire server, detectors, hot-reload, and metrics"
```

---

## Task 15: Integration tests

**Files:**
- Create: `tests/integration.rs`

- [ ] **Step 1: Write the integration test**

Create `tests/integration.rs`:

```rust
//! End-to-end tests: start a stub upstream + purple-wolf, drive real HTTP.
use std::process::{Child, Command};
use std::time::Duration;

struct Servers {
    upstream: Child,
    waf: Child,
}

impl Drop for Servers {
    fn drop(&mut self) {
        let _ = self.upstream.kill();
        let _ = self.waf.kill();
    }
}

/// Start a stub upstream (echo 200) and purple-wolf with the given config text.
fn start(config: &str, waf_port: u16, upstream_port: u16) -> Servers {
    let dir = std::env::temp_dir().join(format!("pw-test-{waf_port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("purple-wolf.toml");
    std::fs::write(&cfg_path, config).unwrap();

    let upstream = Command::new("python3")
        .args(["-m", "http.server", &upstream_port.to_string()])
        .current_dir(&dir)
        .spawn()
        .expect("python3 http.server");

    let waf = Command::new(env!("CARGO_BIN_EXE_purple-wolf"))
        .env("PURPLE_WOLF_CONFIG", &cfg_path)
        .spawn()
        .expect("purple-wolf binary");

    std::thread::sleep(Duration::from_millis(1500));
    Servers { upstream, waf }
}

fn config(mode: &str, waf_port: u16, upstream_port: u16) -> String {
    format!(
        r#"
mode = "{mode}"
fail_mode = "fail_open"
upstream = "http://127.0.0.1:{upstream_port}"
listen = "0.0.0.0:{waf_port}"
[body]
max_inspect_bytes = 1048576
over_cap = "pass"
[groups.injection]
enabled = true
mode = "enforce"
[groups.signatures]
enabled = true
mode = "enforce"
[groups.structural]
enabled = true
mode = "enforce"
[groups.reputation]
enabled = false
mode = "monitor"
"#
    )
}

fn get(port: u16, path: &str) -> u16 {
    let out = Command::new("curl")
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}",
               &format!("http://127.0.0.1:{port}{path}")])
        .output()
        .expect("curl");
    String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0)
}

#[test]
fn enforce_mode_blocks_sqli_and_allows_clean() {
    let _s = start(&config("enforce", 18081, 13001), 18081, 13001);
    assert_eq!(get(18081, "/"), 200, "clean request should be forwarded");
    assert_eq!(
        get(18081, "/?id=1%27%20OR%20%271%27%3D%271"),
        403,
        "SQLi should be blocked in enforce mode"
    );
}

#[test]
fn monitor_mode_allows_sqli() {
    let _s = start(&config("monitor", 18082, 13002), 18082, 13002);
    assert_eq!(
        get(18082, "/?id=1%27%20OR%20%271%27%3D%271"),
        200,
        "SQLi should pass through in monitor mode"
    );
}
```

- [ ] **Step 2: Run the integration tests**

Run: `cargo build --release && cargo test --test integration -- --test-threads=1`
Expected: both tests PASS (`--test-threads=1` so the ports/servers don't collide).

- [ ] **Step 3: Commit**

```bash
git add tests/integration.rs
git commit -m "test: end-to-end proxy enforce and monitor modes"
```

---

## Task 16: Container image & K8s sidecar example

**Files:**
- Create: `deploy/Dockerfile`, `deploy/sidecar-example.yaml`, `.dockerignore`

- [ ] **Step 1: Create `.dockerignore`**

```
target
docs
.git
```

- [ ] **Step 2: Create `deploy/Dockerfile`**

```dockerfile
# Build a fully static musl binary, ship it on scratch.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN rustup target add x86_64-unknown-linux-musl \
 && cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/purple-wolf /purple-wolf
COPY config/purple-wolf.toml /config/purple-wolf.toml
ENV PURPLE_WOLF_CONFIG=/config/purple-wolf.toml
EXPOSE 8080 9090
ENTRYPOINT ["/purple-wolf"]
```

- [ ] **Step 3: Build the image and check its size**

Run: `docker build -f deploy/Dockerfile -t purple-wolf:dev . && docker images purple-wolf:dev`
Expected: image builds; `SIZE` column is single-digit MB.

- [ ] **Step 4: Create `deploy/sidecar-example.yaml`**

```yaml
# Example: add purple-wolf as a sidecar in front of an app container.
# The app's Service targetPort must point at 8080 (the WAF), not the app port.
apiVersion: v1
kind: ConfigMap
metadata:
  name: purple-wolf-config
data:
  purple-wolf.toml: |
    mode = "monitor"
    fail_mode = "fail_open"
    upstream = "http://127.0.0.1:3000"
    listen = "0.0.0.0:8080"
    [body]
    max_inspect_bytes = 1048576
    over_cap = "pass"
    [groups.injection]
    enabled = true
    mode = "enforce"
    [groups.signatures]
    enabled = true
    mode = "enforce"
    [groups.structural]
    enabled = true
    mode = "monitor"
    [groups.reputation]
    enabled = false
    mode = "monitor"
---
# Patch to merge into an existing app Deployment's pod spec:
#   spec.template.spec.containers: add the purple-wolf container below.
#   The app container keeps listening on 3000; purple-wolf listens on 8080.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: example-app
spec:
  template:
    spec:
      containers:
        - name: purple-wolf
          image: purple-wolf:dev
          ports:
            - { name: waf, containerPort: 8080 }
            - { name: metrics, containerPort: 9090 }
          resources:
            requests: { cpu: 25m, memory: 32Mi }
            limits: { cpu: 250m, memory: 64Mi }
          livenessProbe:
            tcpSocket: { port: 8080 }
            periodSeconds: 5
          volumeMounts:
            - { name: waf-config, mountPath: /config }
      volumes:
        - name: waf-config
          configMap: { name: purple-wolf-config }
---
apiVersion: v1
kind: Service
metadata:
  name: example-app
spec:
  selector:
    app: example-app
  ports:
    - name: http
      port: 80
      targetPort: 8080   # routes to purple-wolf, which forwards to the app
```

- [ ] **Step 5: Commit**

```bash
git add deploy/ .dockerignore
git commit -m "feat: static container image and K8s sidecar example"
```

---

## Self-Review Notes

- **Spec coverage:** topology (Tasks 13–16), components (Tasks 2–13 map 1:1 to the spec's component table), hybrid engine (Tasks 6–9), body cap (Task 13 `read_body`/`over_cap`), config model + hot-reload (Tasks 2, 11, 14), monitor mode + fail mode (Tasks 10, 13, 15), error handling (Task 13 `catch_unwind`, 502, config-reload retention), observability (Task 12, 14), size targets (Task 1 profile, Task 16 musl/scratch), testing (per-task unit tests + Task 15). All spec sections covered.
- **§13 open items resolved by this plan:** libinjection FFI uses a hand-written `extern` block + vendored C built with `cc` (Task 5); HTTP/1.1 is served by axum (HTTP/2 from Traefik is out of scope for v1 — Traefik→sidecar over localhost defaults to HTTP/1.1); config reload has no debounce in v1 (a redundant reload is cheap and idempotent).
- **Type consistency:** `RequestView::build`, `Verdict`, `Group`, `GroupMode`, `Decision`, `Action`, `Rules`, `Engine`, `AppState` signatures are identical across all tasks that reference them.
- **Known v1 limitation carried from spec §7.2:** total process death is fail-closed regardless of `fail_mode`; mitigated by the liveness probe in Task 16 and per-request `catch_unwind` in Task 13.
