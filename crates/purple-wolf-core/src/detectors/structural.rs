use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request::Request;

const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_COUNT: usize = 100;

/// Plain-logic anomaly checks: method allowlist, header size/count limits.
pub struct StructuralDetector;

impl Detector for StructuralDetector {
    fn group(&self) -> Group {
        Group::Structural
    }

    fn inspect(&self, req: &Request) -> Vec<Verdict> {
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
                detail: format!(
                    "{} header bytes exceeds {}",
                    req.header_bytes, MAX_HEADER_BYTES
                ),
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

    fn ip() -> IpAddr {
        "1.2.3.4".parse().unwrap()
    }

    #[test]
    fn flags_disallowed_method() {
        let req = Request::build("TRACE", "h", "/", "", vec![], vec![], false, ip());
        let v = StructuralDetector.inspect(&req);
        assert!(v.iter().any(|x| x.rule == "method_not_allowed"));
    }

    #[test]
    fn flags_too_many_headers() {
        let headers: Vec<(String, String)> =
            (0..150).map(|i| (format!("x-{i}"), "v".into())).collect();
        let req = Request::build("GET", "h", "/", "", headers, vec![], false, ip());
        let v = StructuralDetector.inspect(&req);
        assert!(v.iter().any(|x| x.rule == "too_many_headers"));
    }

    #[test]
    fn flags_oversized_headers() {
        let headers = vec![("x-big".into(), "a".repeat(17 * 1024))];
        let req = Request::build("GET", "h", "/", "", headers, vec![], false, ip());
        let v = StructuralDetector.inspect(&req);
        assert!(v.iter().any(|x| x.rule == "headers_too_large"));
    }

    #[test]
    fn normal_request_is_clean() {
        let req = Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![("accept".into(), "*/*".into())],
            vec![],
            false,
            ip(),
        );
        assert!(StructuralDetector.inspect(&req).is_empty());
    }
}
