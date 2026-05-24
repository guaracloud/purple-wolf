//! HTTP request normalization and client-IP resolution.
use percent_encoding::percent_decode_str;
use std::net::IpAddr;

/// A normalized, decoded view of one HTTP request. Detectors read this only.
#[derive(Debug, Clone)]
pub struct Request {
    /// HTTP method of the inspected request, upper-cased.
    pub method: String,
    /// Lowercased hostname from the request.
    pub host: String,
    /// Percent-decoded request path.
    pub path: String,
    /// Raw query string (verbatim, undecoded), or `None` when absent/empty.
    /// Used by the audit log so attack payloads in query parameters are preserved.
    raw_query: Option<String>,
    /// Decoded query parameters: (name, value).
    pub query_params: Vec<(String, String)>,
    /// Header list with lowercased names.
    pub headers: Vec<(String, String)>,
    /// Total byte size of all header names and values combined.
    pub header_bytes: usize,
    /// Lossy UTF-8 of the body, for text-based detectors.
    pub body_text: String,
    /// Whether the body was read and is available for inspection.
    pub body_inspected: bool,
    /// Source IP address, resolved from proxy headers or direct peer.
    pub source_ip: IpAddr,
}

impl Request {
    /// Build a view. `raw_query` is the part after `?` (may be empty).
    // A normalized request view legitimately has many independent inputs; a
    // dedicated Params struct would just shuffle the names around.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        method: &str,
        host: &str,
        path: &str,
        raw_query: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        body_inspected: bool,
        source_ip: IpAddr,
    ) -> Request {
        let query_params = parse_query(raw_query);
        let header_bytes: usize = headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        let body_text = String::from_utf8_lossy(&body).into_owned();
        let headers = headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        let raw_query = if raw_query.is_empty() {
            None
        } else {
            Some(raw_query.to_string())
        };
        Request {
            method: method.to_ascii_uppercase(),
            host: host.to_ascii_lowercase(),
            path: decode(path),
            raw_query,
            query_params,
            headers,
            header_bytes,
            body_text,
            body_inspected,
            source_ip,
        }
    }

    /// The original raw query string (verbatim, undecoded), if any.
    pub fn raw_query(&self) -> Option<&str> {
        self.raw_query.as_deref()
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

    /// Look up a header by name. The lookup is case-insensitive regardless of
    /// the caller's casing.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
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

/// Derive the client's source IP from proxy headers, falling back to the
/// direct peer address.
///
/// Resolution order:
/// 1. `X-Forwarded-For` — use the leftmost valid IP (first trustworthy hop).
/// 2. `X-Real-IP` — use if present and parseable.
/// 3. `peer` — direct connection address.
///
/// Header lookup is case-insensitive. Malformed or missing values are skipped.
pub fn client_ip(headers: &[(String, String)], peer: IpAddr) -> IpAddr {
    // Walk headers for X-Forwarded-For (case-insensitive).
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("x-forwarded-for") {
            for part in v.split(',') {
                if let Ok(ip) = part.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    // Fall through to X-Real-IP.
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("x-real-ip") {
            if let Ok(ip) = v.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "1.2.3.4".parse().unwrap()
    }

    fn peer() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    // ── Request tests ────────────────────────────────────────────────────────

    #[test]
    fn decodes_query_params() {
        let v = Request::build(
            "get", "Example.COM", "/search",
            "q=%27%20OR%201%3D1", vec![], vec![], false, ip(),
        );
        assert_eq!(v.method, "GET");
        assert_eq!(v.host, "example.com");
        assert_eq!(v.query_params, vec![("q".to_string(), "' OR 1=1".to_string())]);
    }

    #[test]
    fn inspectable_fields_skips_uninspected_body() {
        let v = Request::build(
            "POST", "h", "/p", "a=1",
            vec![], b"payload".to_vec(), false, ip(),
        );
        assert!(!v.inspectable_fields().contains(&"payload"));
        let v2 = Request::build(
            "POST", "h", "/p", "a=1",
            vec![], b"payload".to_vec(), true, ip(),
        );
        assert!(v2.inspectable_fields().contains(&"payload"));
    }

    #[test]
    fn raw_query_is_preserved_when_present_and_none_when_empty() {
        let v = Request::build(
            "GET", "h", "/s", "q=%27%20OR%201%3D1",
            vec![], vec![], false, ip(),
        );
        assert_eq!(v.raw_query(), Some("q=%27%20OR%201%3D1"));

        let v2 = Request::build(
            "GET", "h", "/s", "",
            vec![], vec![], false, ip(),
        );
        assert_eq!(v2.raw_query(), None);
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let v = Request::build(
            "GET", "h", "/", "",
            vec![("User-Agent".to_string(), "curl".to_string())],
            vec![], false, ip(),
        );
        assert_eq!(v.header("user-agent"), Some("curl"));
    }

    // ── client_ip tests ──────────────────────────────────────────────────────

    #[test]
    fn client_ip_uses_xff_single() {
        let h = vec![("x-forwarded-for".to_string(), "203.0.113.7".to_string())];
        assert_eq!(client_ip(&h, peer()), "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_uses_xff_leftmost_parseable_with_spaces() {
        let h = vec![(
            "x-forwarded-for".to_string(),
            " 203.0.113.7 , 10.0.0.1 , 10.0.0.2".to_string(),
        )];
        assert_eq!(client_ip(&h, peer()), "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_falls_through_xff_garbage_to_next_valid() {
        let h = vec![(
            "x-forwarded-for".to_string(),
            "not-an-ip, 198.51.100.5".to_string(),
        )];
        assert_eq!(client_ip(&h, peer()), "198.51.100.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_uses_x_real_ip_when_no_xff() {
        let h = vec![("x-real-ip".to_string(), "198.51.100.9".to_string())];
        assert_eq!(client_ip(&h, peer()), "198.51.100.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_falls_back_to_peer_when_no_headers() {
        let h: Vec<(String, String)> = vec![];
        assert_eq!(client_ip(&h, peer()), peer());
    }

    #[test]
    fn client_ip_falls_back_to_peer_when_both_unparseable() {
        let h = vec![
            ("x-forwarded-for".to_string(), "not-an-ip".to_string()),
            ("x-real-ip".to_string(), "also-not".to_string()),
        ];
        assert_eq!(client_ip(&h, peer()), peer());
    }
}
