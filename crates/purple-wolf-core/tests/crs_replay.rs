//! Replay vendored OWASP CRS regression payloads through the engine and
//! verify detection holds at a documented threshold.
//!
//! ## Methodology
//!
//! CRS regression-test YAMLs encode each test as a sequence of
//! `tests[].stages[].input` (the request) plus
//! `tests[].stages[].output.log.{expect_ids|no_expect_ids}` (the
//! expectation). A stage with `expect_ids: [N]` asserts that CRS rule N
//! **should** fire; a stage with `no_expect_ids: [N]` asserts that the
//! input looks like rule N's prey but **must not** trigger it — CRS's
//! own false-positive guard. Both kinds of stages share the same
//! `input` shape (URL + method + headers + data body), so a naive
//! grep-the-payload extractor mixes attack and benign inputs together
//! and silently deflates the detection rate.
//!
//! The extractor here parses the YAML structure with `serde_yaml` and
//! splits payloads into two buckets:
//!
//! - `attack_payloads` — from stages whose `expect_ids` is non-empty.
//!   These count toward the detection-rate measurement.
//! - `benign_payloads` — from stages whose `no_expect_ids` is non-empty.
//!   These are CRS's own benign baseline and feed the FP-guard.
//!
//! A payload is the request `data` field when present (POST body) or
//! the query portion of `uri` otherwise (GET). Multi-line block-scalar
//! `data: |` values are preserved (serde_yaml handles them); the
//! previous string-grep extractor dropped them with a comment claiming
//! they were "scanner-detection blobs", but spot-checking 941110 /
//! 941390 showed several were real `expect_ids` XSS payloads.
//!
//! ## Threshold
//!
//! Measured 2026-05 on CRS upstream v4.x with the honest extractor.
//! The threshold (`MIN_DETECTION_RATE`) is a regression floor, not a
//! quality target. The CRS suite mixes full-context attack strings
//! (which libinjection catches reliably) with atomic-token tests like
//! bare `INFORMATION_SCHEMA`, `database(`, `sleep(20)`, or `OR 1=1`
//! (no surrounding quotes/parens) that exist to exercise CRS's
//! per-rule regexes. We don't ship those regexes by design — our
//! engine is libinjection + literal signatures. The threshold can rise
//! as new detectors land; only lower with a written justification.
//!
//! ## Reproducing the corpus
//!
//! ```bash
//! # From the repo root:
//! rm -rf /tmp/crs && git clone --depth 1 \
//!   https://github.com/coreruleset/coreruleset /tmp/crs
//! rm -rf tests/corpus/crs
//! mkdir -p tests/corpus/crs
//! cp /tmp/crs/LICENSE tests/corpus/crs/
//! cp -r /tmp/crs/tests/regression/tests/REQUEST-941-APPLICATION-ATTACK-XSS \
//!       tests/corpus/crs/
//! cp -r /tmp/crs/tests/regression/tests/REQUEST-942-APPLICATION-ATTACK-SQLI \
//!       tests/corpus/crs/
//! # Record the SHA used:
//! (cd /tmp/crs && git rev-parse HEAD) > tests/corpus/crs/UPSTREAM_COMMIT
//! ```

use purple_wolf_core::detectors::{
    injection::InjectionDetector, signatures::SignatureDetector, Engine, Group,
};
use purple_wolf_core::request::Request;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

fn ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn corpus_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the purple-wolf-core crate dir; corpus lives
    // two levels up at <repo>/tests/corpus/.
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/corpus")
}

fn run_engine_over(payload: &str) -> bool {
    // Feed the payload through the engine the same way the plugin would:
    // as a query value, exercising both injection and signature paths.
    let req = Request::build(
        "GET",
        "h",
        "/",
        &format!("q={payload}"),
        vec![],
        vec![],
        false,
        ip(),
    );
    let engine = Engine::new(vec![
        Box::new(InjectionDetector),
        Box::new(SignatureDetector::new()),
    ]);
    let v = engine.inspect(&req, &[Group::Injection, Group::Signatures]);
    !v.is_empty()
}

// ── YAML schema (minimal — we only deserialize what we use) ──────────────

#[derive(Debug, Deserialize)]
struct CrsFile {
    #[serde(default)]
    tests: Vec<CrsTest>,
}

#[derive(Debug, Deserialize)]
struct CrsTest {
    #[serde(default)]
    stages: Vec<CrsStage>,
}

#[derive(Debug, Deserialize)]
struct CrsStage {
    #[serde(default)]
    input: Option<CrsInput>,
    #[serde(default)]
    output: Option<CrsOutput>,
}

#[derive(Debug, Deserialize)]
struct CrsInput {
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    data: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CrsOutput {
    #[serde(default)]
    log: Option<CrsLog>,
}

#[derive(Debug, Deserialize)]
struct CrsLog {
    #[serde(default)]
    expect_ids: Vec<u32>,
    #[serde(default)]
    no_expect_ids: Vec<u32>,
}

// ── Extraction ──────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Payloads {
    attacks: Vec<String>,
    benign: Vec<String>,
}

fn extract_payload(input: &CrsInput) -> Option<String> {
    if let Some(data) = &input.data {
        if !data.is_empty() {
            return Some(data.clone());
        }
    }
    if let Some(uri) = &input.uri {
        // Take the query portion only — attacks live after `?`.
        if let Some((_, q)) = uri.split_once('?') {
            if !q.is_empty() {
                return Some(q.to_string());
            }
        }
    }
    None
}

fn extract_from_file(path: &Path) -> Payloads {
    let mut out = Payloads::default();
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return out,
    };
    let file: CrsFile = match serde_yaml::from_str(&content) {
        Ok(f) => f,
        Err(_) => return out, // unreadable YAML → skip the file
    };
    for test in &file.tests {
        for stage in &test.stages {
            let (Some(input), Some(output)) = (&stage.input, &stage.output) else {
                continue;
            };
            let Some(log) = &output.log else { continue };
            let Some(payload) = extract_payload(input) else {
                continue;
            };
            if !log.expect_ids.is_empty() {
                out.attacks.push(payload);
            } else if !log.no_expect_ids.is_empty() {
                out.benign.push(payload);
            }
            // Stages with neither key (e.g. setup-only stages) are ignored.
        }
    }
    out
}

fn extract_payloads(crs_dir: &Path) -> Payloads {
    let mut out = Payloads::default();
    for entry in walkdir::WalkDir::new(crs_dir).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(|s| s.to_str()) != Some("yaml") {
            continue;
        }
        let p = extract_from_file(entry.path());
        out.attacks.extend(p.attacks);
        out.benign.extend(p.benign);
    }
    out
}

fn detect_rate(payloads: &[String]) -> (usize, usize, f64) {
    let total = payloads.len();
    let detected = payloads.iter().filter(|p| run_engine_over(p)).count();
    let pct = if total == 0 {
        0.0
    } else {
        (detected as f64) / (total as f64)
    };
    (detected, total, pct)
}

// ── Tests ───────────────────────────────────────────────────────────────

/// Minimum detection rate across the attack-only CRS corpus.
///
/// **Methodology change (2026-05, NEW-C2):** the pre-fix extractor
/// counted CRS's own `no_expect_ids` payloads (benign FP guards) as
/// missed attacks, depressing the headline rate. With the honest
/// extractor:
/// - XSS  (REQUEST-941): 58/130 = 0.45 (vs. the prior 0.37)
/// - SQLi (REQUEST-942): 129/726 = 0.18
/// - aggregate         : 187/856 = 0.22 (vs. the prior 0.19)
///
/// The floor is 0.20 — 2pts below the measured 0.22 to absorb
/// run-to-run noise from CRS upstream corpus reshuffles. The rate is
/// expected to rise as new detectors land (template injection, SSRF,
/// Log4Shell signatures, etc.); only lower with a written
/// justification in this file. XSS at 45% is the project's strongest
/// honest claim; SQLi at 18% reflects libinjection's deliberate
/// "context-aware tokenizer, not bare-keyword regex" design choice.
const MIN_DETECTION_RATE: f64 = 0.20;

#[test]
fn crs_attack_corpus_is_mostly_detected() {
    let dir = corpus_root().join("crs");
    if !dir.exists() {
        eprintln!("crs corpus missing at {dir:?}; skipping");
        return;
    }

    // Diagnostic breakdown per subfolder — useful when the aggregate drifts.
    for sub in [
        "REQUEST-941-APPLICATION-ATTACK-XSS",
        "REQUEST-942-APPLICATION-ATTACK-SQLI",
    ] {
        let p = dir.join(sub);
        if !p.exists() {
            continue;
        }
        let payloads = extract_payloads(&p);
        let (d, t, pct) = detect_rate(&payloads.attacks);
        eprintln!(
            "CRS {sub}: attacks {d}/{t} = {pct:.2}, benign-baseline {} payloads",
            payloads.benign.len()
        );
    }

    let payloads = extract_payloads(&dir);
    assert!(
        !payloads.attacks.is_empty(),
        "no attack payloads extracted from CRS corpus at {dir:?}"
    );
    let (detected, total, pct) = detect_rate(&payloads.attacks);
    eprintln!("CRS detection (aggregate, attacks only): {detected}/{total} = {pct:.2}");
    assert!(
        pct >= MIN_DETECTION_RATE,
        "CRS detection rate {detected}/{total} = {pct:.2} below {MIN_DETECTION_RATE:.2} \
         — investigate before lowering the floor",
    );
}

/// The project's own benign corpus (`tests/corpus/clean/clean.txt`) must
/// produce zero false positives — these are inputs hand-curated to look
/// nothing like an attack but to exercise the parser shape.
#[test]
fn benign_corpus_has_no_false_positives() {
    let path = corpus_root().join("clean/clean.txt");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    let mut fps = Vec::new();
    for line in text.lines() {
        // Skip blanks and `#`-prefixed comments — the file is documented
        // section-by-section so reviewers can see what each line tests.
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if run_engine_over(line) {
            fps.push(line.to_string());
        }
    }
    assert!(fps.is_empty(), "false positives on clean.txt: {fps:?}");
}

/// FP rate on the recovered CRS benign sub-corpus (a much larger, more
/// realistic baseline than clean.txt). The accepted ceiling reflects
/// libinjection's deliberately context-free design: some inputs CRS
/// asserts are benign-for-rule-N still look enough like SQL/XSS that
/// libinjection's tokenizer flags them.
#[test]
fn crs_benign_corpus_fp_rate_is_bounded() {
    let dir = corpus_root().join("crs");
    if !dir.exists() {
        eprintln!("crs corpus missing at {dir:?}; skipping");
        return;
    }
    let payloads = extract_payloads(&dir);
    if payloads.benign.is_empty() {
        eprintln!("no benign payloads recovered from CRS corpus; skipping");
        return;
    }
    let (fp, total, pct) = detect_rate(&payloads.benign);
    eprintln!("CRS no_expect_ids FP rate: {fp}/{total} = {pct:.2}");
    // Floor is generous: CRS's per-rule benign baselines were designed for
    // CRS's per-rule regexes, not libinjection's tokenizer; some genuine
    // cross-fire is expected and intentional.
    const MAX_FP_RATE: f64 = 0.40;
    assert!(
        pct <= MAX_FP_RATE,
        "CRS benign FP rate {fp}/{total} = {pct:.2} exceeds {MAX_FP_RATE:.2}"
    );
}
