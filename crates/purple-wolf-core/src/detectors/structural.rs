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

        // Control-byte checks over the decoded path and decoded query values.
        // After decode-to-fixpoint, `%00` is a literal NUL (LFI path-
        // truncation) and `%0d`/`%0a` are literal CR/LF (response-splitting /
        // header-injection adjacency). Benign URLs never carry these, so the
        // checks are high-precision; each is a single byte scan (memchr-class).
        let mut has_null = req.path.as_bytes().contains(&0);
        let mut has_crlf = req.path.contains(['\r', '\n']);
        for (_, value) in &req.query_params {
            if !has_null && value.as_bytes().contains(&0) {
                has_null = true;
            }
            if !has_crlf && value.contains(['\r', '\n']) {
                has_crlf = true;
            }
            if has_null && has_crlf {
                break;
            }
        }
        if has_null {
            verdicts.push(Verdict {
                group: Group::Structural,
                rule: "null_byte",
                severity: Severity::Medium,
                detail: "NUL byte in request path or query".to_string(),
            });
        }
        if has_crlf {
            verdicts.push(Verdict {
                group: Group::Structural,
                rule: "crlf_injection",
                severity: Severity::Medium,
                detail: "CR/LF in request path or query".to_string(),
            });
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

    // ── Null-byte and CRLF checks (Tier 2.11) ───────────────────────────────

    #[test]
    fn flags_null_byte_in_path() {
        // `%00` decodes to a NUL byte — a classic LFI path-truncation
        // primitive (`/etc/passwd%00.png`). After decode-to-fixpoint the
        // path carries a literal NUL the structural check must catch.
        let req = Request::build(
            "GET",
            "h",
            "/download/%00/etc/passwd",
            "",
            vec![],
            vec![],
            false,
            ip(),
        );
        let v = StructuralDetector.inspect(&req);
        assert!(v.iter().any(|x| x.rule == "null_byte"), "verdicts: {v:?}");
    }

    #[test]
    fn flags_null_byte_in_query_value() {
        let req = Request::build("GET", "h", "/f", "name=a%00b", vec![], vec![], false, ip());
        let v = StructuralDetector.inspect(&req);
        assert!(v.iter().any(|x| x.rule == "null_byte"), "verdicts: {v:?}");
    }

    #[test]
    fn flags_crlf_in_query_value() {
        // `%0d%0a` decodes to CRLF — response-splitting / header-injection
        // adjacency when reflected.
        let req = Request::build(
            "GET",
            "h",
            "/redirect",
            "url=x%0d%0aSet-Cookie:+evil=1",
            vec![],
            vec![],
            false,
            ip(),
        );
        let v = StructuralDetector.inspect(&req);
        assert!(
            v.iter().any(|x| x.rule == "crlf_injection"),
            "verdicts: {v:?}"
        );
    }

    #[test]
    fn flags_crlf_in_path() {
        let req = Request::build("GET", "h", "/a%0db", "", vec![], vec![], false, ip());
        let v = StructuralDetector.inspect(&req);
        assert!(
            v.iter().any(|x| x.rule == "crlf_injection"),
            "verdicts: {v:?}"
        );
    }

    #[test]
    fn benign_request_has_no_null_or_crlf() {
        // Ordinary multi-param request with no control bytes must stay clean.
        let req = Request::build(
            "GET",
            "h",
            "/search",
            "q=hello+world&lang=en&page=2",
            vec![("accept".into(), "*/*".into())],
            vec![],
            false,
            ip(),
        );
        let v = StructuralDetector.inspect(&req);
        assert!(
            !v.iter()
                .any(|x| x.rule == "null_byte" || x.rule == "crlf_injection"),
            "benign request must not flag control-byte rules: {v:?}"
        );
    }
}
