use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::ffi;
use crate::request::Request;

/// SQLi/XSS detector backed by libinjection.
pub struct InjectionDetector;

impl Detector for InjectionDetector {
    fn group(&self) -> Group {
        Group::Injection
    }

    fn inspect(&self, req: &Request) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        let mut sqli_found = false;
        for field in req.inspectable_fields() {
            if ffi::is_sqli(field) {
                sqli_found = true;
                verdicts.push(Verdict {
                    group: Group::Injection,
                    rule: "sqli",
                    severity: Severity::Critical,
                    detail: format!("SQLi in field: {}", truncate_bytes(field)),
                });
            }
            if ffi::is_xss(field) {
                verdicts.push(Verdict {
                    group: Group::Injection,
                    rule: "xss",
                    severity: Severity::High,
                    detail: format!("XSS in field: {}", truncate_bytes(field)),
                });
            }
        }

        // User-Agent suffix probe (documented round-2 gap). libinjection
        // fingerprints `Mozilla/5.0 1 OR 1=1` as a User-Agent *string* and
        // misses the trailing SQL. Re-probe the UA's suffix — the text after
        // the first ASCII space and after the last `)` — so the isolated SQL
        // tail reaches the tokenizer without the UA-shaped prefix steering
        // the verdict. Only runs when no SQLi was found above, which also
        // dedupes: a UA whose whole value already flagged is not re-counted.
        if !sqli_found {
            if let Some(ua) = req.user_agent() {
                for cand in ua_suffix_candidates(ua).into_iter().flatten() {
                    if ffi::is_sqli(cand.as_bytes()) {
                        verdicts.push(Verdict {
                            group: Group::Injection,
                            rule: "sqli",
                            severity: Severity::Critical,
                            detail: format!(
                                "SQLi in User-Agent suffix: {}",
                                truncate_bytes(cand.as_bytes())
                            ),
                        });
                        break;
                    }
                }
            }
        }
        verdicts
    }
}

/// Candidate suffixes of a User-Agent value to re-probe for SQLi, with the
/// narrowest browser-tail candidate first. Returns only substrings that differ
/// from the whole value (the whole value was already probed in the main loop).
/// A browser UA looks
/// like `Mozilla/5.0 (platform) Engine/ver`, so the SQL an attacker appends
/// lives after the first space or after the parenthesized platform block.
fn ua_suffix_candidates(ua: &str) -> [Option<&str>; 2] {
    // After the last ')': covers `…(X11; Linux) <sql>`.
    let after_paren = ua.rfind(')').and_then(|idx| {
        let tail = ua[idx + 1..].trim();
        (!tail.is_empty() && tail.len() < ua.len()).then_some(tail)
    });

    // After the first ASCII space: covers `Mozilla/5.0 <sql>` (no parens).
    let after_space = ua.find(' ').and_then(|idx| {
        let tail = ua[idx + 1..].trim();
        (!tail.is_empty() && tail.len() < ua.len() && Some(tail) != after_paren).then_some(tail)
    });

    // The fixed-size representation keeps the benign browser path off the
    // allocator while retaining the original candidate order and dedupe rules.
    [after_paren, after_space]
}

/// Build a short, log-safe representation of an attacker-controlled byte
/// slice for the audit-log `blocked_detail` field.
///
/// - Lossy-converts bytes to a string first (the audit log is JSON-text,
///   so we can't carry raw bytes through). Non-UTF-8 bytes become
///   U+FFFD in this preview — but the detector already ran against the
///   raw bytes (NEW-I2), so an attack hidden in non-UTF-8 still fires;
///   we just lose a few characters of the audit-detail preview.
/// - Truncates to 80 chars to keep log lines bounded.
/// - Replaces ASCII control characters (`\x00..=\x1F`, `\x7f`) with `.` so
///   a payload containing `\r\n` cannot force a downstream regex-based log
///   parser to read across what it thinks is a line boundary (NEW-I1).
fn truncate_bytes(s: &[u8]) -> String {
    String::from_utf8_lossy(s)
        .chars()
        .take(80)
        .map(|c| {
            if (c as u32) < 0x20 || c == '\x7f' {
                '.'
            } else {
                c
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::net::IpAddr;

    fn req_with_query(q: &str) -> Request {
        Request::build(
            "GET",
            "h",
            "/s",
            q,
            vec![],
            vec![],
            false,
            "1.2.3.4".parse::<IpAddr>().unwrap(),
        )
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

    #[test]
    fn flags_double_encoded_sqli_in_query() {
        // Double-encoded `' OR '1'='1`. A single-pass decoder would inspect
        // the still-encoded `%27...` literal and miss it; decode-to-fixpoint
        // recovers the cleartext SQLi for libinjection.
        let v = InjectionDetector.inspect(&req_with_query(
            "id=%2527%2520OR%2520%25271%2527%253D%25271",
        ));
        assert!(
            v.iter().any(|x| x.rule == "sqli"),
            "double-encoded SQLi must be detected after fixpoint decode; verdicts: {v:?}"
        );
    }

    #[test]
    fn benign_percent_literal_does_not_false_positive() {
        // A benign value carrying a literal percent sign must decode to
        // `50%off` and not trip any injection verdict — decode-to-fixpoint
        // must not manufacture false positives from ordinary `%` content.
        let v = InjectionDetector.inspect(&req_with_query("discount=50%25off&items=2"));
        assert!(
            v.is_empty(),
            "benign percent literal should not flag: {v:?}"
        );
    }

    // ── Header inspection (fix for v0.2 C-1) ────────────────────────────────

    fn req_with_header(name: &str, value: &str) -> Request {
        Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![(name.into(), value.into())],
            vec![],
            false,
            "1.2.3.4".parse::<IpAddr>().unwrap(),
        )
    }

    #[test]
    fn flags_sqli_in_cookie_header() {
        let v = InjectionDetector.inspect(&req_with_header("Cookie", "id=1' OR '1'='1"));
        assert!(v.iter().any(|x| x.rule == "sqli"), "verdicts: {v:?}");
    }

    #[test]
    fn flags_sqli_in_referer_header() {
        let v = InjectionDetector.inspect(&req_with_header("Referer", "http://x/?id=1' OR '1'='1"));
        assert!(v.iter().any(|x| x.rule == "sqli"), "verdicts: {v:?}");
    }

    #[test]
    fn flags_sqli_in_custom_x_header() {
        let v = InjectionDetector.inspect(&req_with_header("X-User", "' OR 1=1 --"));
        assert!(v.iter().any(|x| x.rule == "sqli"), "verdicts: {v:?}");
    }

    #[test]
    fn flags_xss_in_referer_header() {
        let v = InjectionDetector.inspect(&req_with_header("Referer", "<script>alert(1)</script>"));
        assert!(v.iter().any(|x| x.rule == "xss"), "verdicts: {v:?}");
    }

    #[test]
    fn benign_cookie_does_not_false_positive() {
        let v = InjectionDetector.inspect(&req_with_header(
            "Cookie",
            "sessionid=abc123; csrftoken=xyz789",
        ));
        assert!(v.is_empty(), "benign cookie should not flag: {v:?}");
    }

    /// Regression guard for NEW-I1: control characters in attacker payloads
    /// must not survive into the audit-log detail string. Pre-fix, a
    /// payload containing `\r\n{"action":"allow"}` would be wrapped in
    /// JSON quotes — safe at the JSON-parser level, but regex-based log
    /// pipelines could be fooled into reading "allow" as the audit action.
    #[test]
    fn truncate_replaces_control_chars() {
        let dangerous = b"1' OR '1'='1\r\n{\"action\":\"allow\"}\x00\x07";
        let safe = super::truncate_bytes(dangerous);
        assert!(!safe.contains('\r'), "CR must be stripped: {safe:?}");
        assert!(!safe.contains('\n'), "LF must be stripped: {safe:?}");
        assert!(!safe.contains('\x00'), "NUL must be stripped: {safe:?}");
        assert!(!safe.contains('\x07'), "BEL must be stripped: {safe:?}");
        // Printable content survives.
        assert!(safe.starts_with("1' OR '1'='1"));
    }

    /// Regression guard for NEW-I4: percent-encoded SQLi in a Cookie value
    /// must still fire. Pre-fix the header was inspected raw only, so a
    /// payload like `id=%27%20OR%201%3D1` reached libinjection as the
    /// literal `%27...` string and never matched.
    #[test]
    fn flags_percent_encoded_sqli_in_cookie() {
        let v =
            InjectionDetector.inspect(&req_with_header("Cookie", "id=%27%20OR%20%271%27%3D%271"));
        assert!(
            v.iter().any(|x| x.rule == "sqli"),
            "percent-encoded cookie SQLi must be inspected; verdicts: {v:?}"
        );
    }

    // ── User-Agent SQLi suffix probe (Tier 2.10) ────────────────────────────

    /// Documented round-2 gap: libinjection fingerprints
    /// `Mozilla/5.0 1 OR 1=1` as a User-Agent *string* and does not flag the
    /// trailing SQL. Re-probing the UA's suffix (after the prefix token /
    /// last `)`) recovers the injection.
    #[test]
    fn flags_mozilla_prefixed_sqli_in_user_agent() {
        let v = InjectionDetector.inspect(&req_with_header("User-Agent", "Mozilla/5.0 1 OR 1=1"));
        assert!(
            v.iter().any(|x| x.rule == "sqli"),
            "Mozilla-prefixed UA SQLi must be detected via suffix probe; verdicts: {v:?}"
        );
    }

    #[test]
    fn flags_sqli_in_user_agent_after_paren() {
        // Real browser UAs end in `)`; an attacker appending SQL after the
        // parenthesized platform block is the common shape.
        let v = InjectionDetector.inspect(&req_with_header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) ' OR '1'='1",
        ));
        assert!(
            v.iter().any(|x| x.rule == "sqli"),
            "UA SQLi after the paren block must be detected; verdicts: {v:?}"
        );
    }

    #[test]
    fn benign_user_agent_does_not_false_positive() {
        // A normal browser UA must not produce any verdict.
        let v = InjectionDetector.inspect(&req_with_header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        ));
        assert!(v.is_empty(), "benign UA must not flag: {v:?}");
    }

    #[test]
    fn user_agent_sqli_not_double_counted() {
        // A UA whose whole value libinjection already flags must yield
        // exactly one sqli verdict — the suffix probe must dedupe, not add
        // a second verdict for the same field.
        let v = InjectionDetector.inspect(&req_with_header("User-Agent", "' OR '1'='1"));
        assert_eq!(
            v.iter().filter(|x| x.rule == "sqli").count(),
            1,
            "UA SQLi must not be double-counted; verdicts: {v:?}"
        );
    }

    #[test]
    fn ua_suffix_candidates_derive_expected_tails() {
        // After the first space.
        assert_eq!(
            super::ua_suffix_candidates("Mozilla/5.0 1 OR 1=1"),
            [None, Some("1 OR 1=1")]
        );
        // After the last ')' (preferred, narrowest first) and after first space.
        assert_eq!(
            super::ua_suffix_candidates("Mozilla/5.0 (X11; Linux) ' OR 1=1"),
            [Some("' OR 1=1"), Some("(X11; Linux) ' OR 1=1")]
        );
        // A single token (no space, no paren) yields no suffix candidate —
        // it was already probed whole in the main loop.
        assert_eq!(super::ua_suffix_candidates("curl/8.4.0"), [None, None]);
        // When both split points yield the same suffix, inspect it once.
        assert_eq!(
            super::ua_suffix_candidates("Mozilla/5.0) 1 OR 1=1"),
            [Some("1 OR 1=1"), None]
        );
    }

    #[test]
    fn realistic_browser_user_agents_do_not_false_positive() {
        // The suffix probe must not turn ordinary browser UAs into SQLi
        // verdicts — the FPR guard for the new probe.
        for ua in [
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "curl/8.4.0",
            "PostmanRuntime/7.36.0",
        ] {
            let v = InjectionDetector.inspect(&req_with_header("User-Agent", ua));
            assert!(v.is_empty(), "benign UA {ua:?} must not flag: {v:?}");
        }
    }
}
