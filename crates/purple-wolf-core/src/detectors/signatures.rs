use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request::Request;
use aho_corasick::AhoCorasick;

/// (literal, rule name, severity) — extend this table to add signatures.
const SIGNATURES: &[(&str, &str, Severity)] = &[
    ("../", "path_traversal", Severity::High),
    ("..\\", "path_traversal", Severity::High),
    ("/etc/passwd", "lfi", Severity::Critical),
    ("$(", "rce_subshell", Severity::Critical),
    // Bare backtick: prone to false positives on Markdown/CMS/JSON traffic.
    // Kept for RCE coverage — retune (e.g. narrow the literal) if noisy.
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
    /// Build a `SignatureDetector` with the compiled static signature set.
    pub fn new() -> SignatureDetector {
        let patterns: Vec<&str> = SIGNATURES.iter().map(|(p, _, _)| *p).collect();
        let matcher = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("static signature set must build");
        SignatureDetector { matcher }
    }
}

impl Default for SignatureDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for SignatureDetector {
    fn group(&self) -> Group {
        Group::Signatures
    }

    fn inspect(&self, req: &Request) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        // Header values (User-Agent, Cookie, Referer, X-*, etc.) are already
        // part of `inspectable_fields()` per the allow-list in `request.rs`.
        let fields = req.inspectable_fields();
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

    fn ip() -> IpAddr {
        "1.2.3.4".parse().unwrap()
    }

    #[test]
    fn flags_path_traversal() {
        let req = Request::build(
            "GET",
            "h",
            "/files",
            "f=../../etc/passwd",
            vec![],
            vec![],
            false,
            ip(),
        );
        let v = SignatureDetector::new().inspect(&req);
        assert!(v
            .iter()
            .any(|x| x.rule == "path_traversal" || x.rule == "lfi"));
    }

    #[test]
    fn flags_scanner_user_agent() {
        let req = Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![("user-agent".into(), "sqlmap/1.7".into())],
            vec![],
            false,
            ip(),
        );
        let v = SignatureDetector::new().inspect(&req);
        assert!(v.iter().any(|x| x.rule == "scanner_ua"));
    }

    #[test]
    fn benign_request_is_clean() {
        let req = Request::build(
            "GET",
            "h",
            "/about",
            "ref=home",
            vec![("user-agent".into(), "Mozilla/5.0".into())],
            vec![],
            false,
            ip(),
        );
        assert!(SignatureDetector::new().inspect(&req).is_empty());
    }

    // ── Header inspection (fix for v0.2 C-1) ────────────────────────────────

    #[test]
    fn flags_lfi_signature_in_cookie() {
        let req = Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![("Cookie".into(), "id=1; path=/etc/passwd".into())],
            vec![],
            false,
            ip(),
        );
        let v = SignatureDetector::new().inspect(&req);
        assert!(v.iter().any(|x| x.rule == "lfi"), "verdicts: {v:?}");
    }

    #[test]
    fn flags_path_traversal_in_custom_x_header() {
        let req = Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![("X-File-Path".into(), "../../etc/secret".into())],
            vec![],
            false,
            ip(),
        );
        let v = SignatureDetector::new().inspect(&req);
        assert!(
            v.iter().any(|x| x.rule == "path_traversal"),
            "verdicts: {v:?}"
        );
    }

    #[test]
    fn user_agent_still_detected_after_inspectable_field_consolidation() {
        // Regression guard: the User-Agent special-case that signatures.rs
        // used to apply was removed once Request::inspectable_fields() began
        // returning header values via the allow-list. This test makes sure
        // scanner-UA detection survives the refactor.
        let req = Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![("user-agent".into(), "sqlmap/1.7".into())],
            vec![],
            false,
            ip(),
        );
        let v = SignatureDetector::new().inspect(&req);
        assert!(v.iter().any(|x| x.rule == "scanner_ua"));
        // And only once, because we no longer scan UA via both inspectable_fields
        // AND a separate special-case loop.
        assert_eq!(v.iter().filter(|x| x.rule == "scanner_ua").count(), 1);
    }
}
