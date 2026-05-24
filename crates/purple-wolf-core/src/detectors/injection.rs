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
}
