use percent_encoding::percent_decode_str;
use std::net::IpAddr;

/// A normalized, decoded view of one HTTP request. Detectors read this only.
#[derive(Debug, Clone)]
pub struct RequestView {
    pub method: String,
    pub host: String,
    pub path: String,
    /// Decoded query parameters: (name, value).
    pub query_params: Vec<(String, String)>,
    /// Header names are lowercased.
    pub headers: Vec<(String, String)>,
    pub header_bytes: usize,
    pub body: Vec<u8>,
    /// Lossy UTF-8 of the body, for text-based detectors.
    pub body_text: String,
    pub body_inspected: bool,
    pub source_ip: IpAddr,
}

impl RequestView {
    /// Build a view. `raw_query` is the part after `?` (may be empty).
    pub fn build(
        method: &str,
        host: &str,
        path: &str,
        raw_query: &str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        body_inspected: bool,
        source_ip: IpAddr,
    ) -> RequestView {
        let query_params = parse_query(raw_query);
        let header_bytes: usize = headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        let body_text = String::from_utf8_lossy(&body).into_owned();
        let headers = headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        RequestView {
            method: method.to_ascii_uppercase(),
            host: host.to_ascii_lowercase(),
            path: decode(path),
            query_params,
            headers,
            header_bytes,
            body,
            body_text,
            body_inspected,
            source_ip,
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "1.2.3.4".parse().unwrap()
    }

    #[test]
    fn decodes_query_params() {
        let v = RequestView::build(
            "get", "Example.COM", "/search",
            "q=%27%20OR%201%3D1", vec![], vec![], false, ip(),
        );
        assert_eq!(v.method, "GET");
        assert_eq!(v.host, "example.com");
        assert_eq!(v.query_params, vec![("q".to_string(), "' OR 1=1".to_string())]);
    }

    #[test]
    fn inspectable_fields_skips_uninspected_body() {
        let v = RequestView::build(
            "POST", "h", "/p", "a=1",
            vec![], b"payload".to_vec(), false, ip(),
        );
        assert!(!v.inspectable_fields().contains(&"payload"));
        let v2 = RequestView::build(
            "POST", "h", "/p", "a=1",
            vec![], b"payload".to_vec(), true, ip(),
        );
        assert!(v2.inspectable_fields().contains(&"payload"));
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let v = RequestView::build(
            "GET", "h", "/", "",
            vec![("User-Agent".to_string(), "curl".to_string())],
            vec![], false, ip(),
        );
        assert_eq!(v.header("user-agent"), Some("curl"));
    }
}
