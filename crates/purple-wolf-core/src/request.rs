//! HTTP request normalization and client-IP resolution.
use percent_encoding::percent_decode_str;
use std::net::IpAddr;

/// Headers whose values are inspected by the detection pipeline.
///
/// Two rules: (a) exact match against [`INSPECTABLE_HEADERS_EXACT`] (after
/// case-fold to lowercase, which `Request::build` already applies), or (b)
/// any header whose name starts with `x-` (the conventional prefix for
/// custom application headers, a frequent injection vector).
///
/// The list is deliberately an allow-list rather than a deny-list: every
/// header here is known to commonly carry user-controlled content that an
/// attacker can use as an injection sink (cookies, the Referer URL, the
/// Host header, raw Authorization payloads, the User-Agent string used by
/// scanner-UA detection). Adding a header is a conservative decision —
/// removing one is a detection regression.
const INSPECTABLE_HEADERS_EXACT: &[&str] =
    &["cookie", "referer", "host", "authorization", "user-agent"];

/// Prefix matched by `inspectable_header_values` in addition to the exact
/// allow-list — custom `X-*` headers are typically user-controllable and
/// therefore inspected.
const INSPECTABLE_HEADER_PREFIX: &str = "x-";

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

    /// Every string a detector should scan: path, param values, body text,
    /// and the value of every inspectable header (see
    /// [`INSPECTABLE_HEADERS_EXACT`]).
    ///
    /// Headers are appended last so the test/detector ordering stays stable
    /// for path/query/body assertions.
    pub fn inspectable_fields(&self) -> Vec<&str> {
        let mut out = vec![self.path.as_str()];
        for (_, v) in &self.query_params {
            out.push(v.as_str());
        }
        if self.body_inspected {
            out.push(self.body_text.as_str());
        }
        out.extend(self.inspectable_header_values());
        out
    }

    /// Values of headers in the inspection allow-list. Used internally by
    /// [`Request::inspectable_fields`]; exposed so detectors that need to
    /// distinguish header values from URL/body inputs (e.g. for severity
    /// or detail formatting) can opt in.
    ///
    /// Header names are matched case-insensitively; `Request::build`
    /// already lowercases stored header names, so a simple `==` /
    /// `starts_with` is enough here.
    pub fn inspectable_header_values(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| {
                INSPECTABLE_HEADERS_EXACT.contains(&k.as_str())
                    || k.starts_with(INSPECTABLE_HEADER_PREFIX)
            })
            .map(|(_, v)| v.as_str())
            .collect()
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
            "get",
            "Example.COM",
            "/search",
            "q=%27%20OR%201%3D1",
            vec![],
            vec![],
            false,
            ip(),
        );
        assert_eq!(v.method, "GET");
        assert_eq!(v.host, "example.com");
        assert_eq!(
            v.query_params,
            vec![("q".to_string(), "' OR 1=1".to_string())]
        );
    }

    #[test]
    fn inspectable_fields_skips_uninspected_body() {
        let v = Request::build(
            "POST",
            "h",
            "/p",
            "a=1",
            vec![],
            b"payload".to_vec(),
            false,
            ip(),
        );
        assert!(!v.inspectable_fields().contains(&"payload"));
        let v2 = Request::build(
            "POST",
            "h",
            "/p",
            "a=1",
            vec![],
            b"payload".to_vec(),
            true,
            ip(),
        );
        assert!(v2.inspectable_fields().contains(&"payload"));
    }

    #[test]
    fn raw_query_is_preserved_when_present_and_none_when_empty() {
        let v = Request::build(
            "GET",
            "h",
            "/s",
            "q=%27%20OR%201%3D1",
            vec![],
            vec![],
            false,
            ip(),
        );
        assert_eq!(v.raw_query(), Some("q=%27%20OR%201%3D1"));

        let v2 = Request::build("GET", "h", "/s", "", vec![], vec![], false, ip());
        assert_eq!(v2.raw_query(), None);
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let v = Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![("User-Agent".to_string(), "curl".to_string())],
            vec![],
            false,
            ip(),
        );
        assert_eq!(v.header("user-agent"), Some("curl"));
    }

    // ── Header inspection (fix for v0.2 C-1) ────────────────────────────────

    #[test]
    fn inspectable_fields_includes_allowlisted_header_values() {
        let v = Request::build(
            "GET",
            "h",
            "/p",
            "q=1",
            vec![
                ("Cookie".into(), "sess=abc; id=42".into()),
                ("Referer".into(), "https://x.example/from".into()),
                ("Authorization".into(), "Bearer tok".into()),
                ("X-User".into(), "victor".into()),
                ("User-Agent".into(), "Mozilla/5.0".into()),
                // Not in the allow-list — must NOT show up:
                ("Accept-Language".into(), "en-US".into()),
                ("Cache-Control".into(), "no-cache".into()),
            ],
            vec![],
            false,
            ip(),
        );
        let fields = v.inspectable_fields();
        assert!(fields.contains(&"sess=abc; id=42"));
        assert!(fields.contains(&"https://x.example/from"));
        assert!(fields.contains(&"Bearer tok"));
        assert!(fields.contains(&"victor"));
        assert!(fields.contains(&"Mozilla/5.0"));
        assert!(!fields.contains(&"en-US"));
        assert!(!fields.contains(&"no-cache"));
    }

    #[test]
    fn inspectable_header_values_matches_x_prefix_case_insensitively() {
        let v = Request::build(
            "GET",
            "h",
            "/",
            "",
            // The mixed-case name is lowercased by Request::build, so the
            // prefix check sees `x-anything` regardless of caller casing.
            vec![("X-Forwarded-For".into(), "1.2.3.4".into())],
            vec![],
            false,
            ip(),
        );
        assert_eq!(v.inspectable_header_values(), vec!["1.2.3.4"]);
    }

    #[test]
    fn header_inspection_preserves_existing_field_order() {
        // path comes first, then query values, then body if inspected, then headers.
        let v = Request::build(
            "POST",
            "h",
            "/path",
            "q=qv",
            vec![("Cookie".into(), "ck".into())],
            b"body".to_vec(),
            true,
            ip(),
        );
        assert_eq!(v.inspectable_fields(), vec!["/path", "qv", "body", "ck"]);
    }

    // ── client_ip tests ──────────────────────────────────────────────────────

    #[test]
    fn client_ip_uses_xff_single() {
        let h = vec![("x-forwarded-for".to_string(), "203.0.113.7".to_string())];
        assert_eq!(
            client_ip(&h, peer()),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_uses_xff_leftmost_parseable_with_spaces() {
        let h = vec![(
            "x-forwarded-for".to_string(),
            " 203.0.113.7 , 10.0.0.1 , 10.0.0.2".to_string(),
        )];
        assert_eq!(
            client_ip(&h, peer()),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_falls_through_xff_garbage_to_next_valid() {
        let h = vec![(
            "x-forwarded-for".to_string(),
            "not-an-ip, 198.51.100.5".to_string(),
        )];
        assert_eq!(
            client_ip(&h, peer()),
            "198.51.100.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_uses_x_real_ip_when_no_xff() {
        let h = vec![("x-real-ip".to_string(), "198.51.100.9".to_string())];
        assert_eq!(
            client_ip(&h, peer()),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
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
