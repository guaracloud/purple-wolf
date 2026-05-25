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
}
