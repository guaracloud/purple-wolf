//! HTTP request normalization and client-IP resolution.
use percent_encoding::percent_decode_str;
use std::net::IpAddr;

/// Headers whose values are inspected by the detection pipeline.
///
/// Two rules: (a) exact match against `INSPECTABLE_HEADERS_EXACT` (after
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
    /// Raw request body, as the host delivered it. Stored as bytes so
    /// non-UTF-8 payloads (e.g. SHIFT-JIS or any high-bit encoding) reach
    /// libinjection in their original form — pre-fix the field was a
    /// lossy `String`, and any invalid UTF-8 sequence became U+FFFD
    /// before detection ran. Detectors should use this through
    /// [`Request::inspectable_fields`] (which returns `&[u8]`) so the
    /// raw bytes are preserved end-to-end. Audit serialization gets a
    /// lossy view via [`Request::body_text_lossy`].
    body: Vec<u8>,
    /// Whether the body was read and is available for inspection.
    pub body_inspected: bool,
    /// Whether the body was truncated at the inspection cap — i.e. the
    /// request carried more body bytes than `maxInspectBytes` and only the
    /// buffered prefix is present in [`Request::body_bytes`]. Surfaced in the
    /// audit log so operators can see when a payload could be hiding past the
    /// cap. Defaults to `false`; set via [`Request::with_truncated_body`].
    pub body_truncated: bool,
    /// Source IP address, resolved from proxy headers or direct peer.
    pub source_ip: IpAddr,
    /// Pre-computed values of inspection-allow-list headers. Each value
    /// appears both raw and (if different) percent-decoded so encoded
    /// payloads are inspected in both forms. Used by detectors via
    /// [`Request::inspectable_fields`]; computed once at `build` time so
    /// the per-detector hot path stays a borrow. Stored as `Vec<u8>`
    /// so detectors see header values as raw bytes (NEW-I2).
    inspectable_headers: Vec<Vec<u8>>,
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
        let headers: Vec<(String, String)> = headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        let inspectable_headers = build_inspectable_headers(&headers);
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
            body,
            body_inspected,
            body_truncated: false,
            source_ip,
            inspectable_headers,
        }
    }

    /// Mark whether the body was truncated at the inspection cap. Builder-
    /// style so existing `Request::build` call sites need no change; the
    /// http-wasm guest sets this when it inspects the buffered prefix of an
    /// over-cap body (so an in-prefix payload is still caught, and the audit
    /// log records that bytes past the cap went un-inspected).
    pub fn with_truncated_body(mut self, truncated: bool) -> Request {
        self.body_truncated = truncated;
        self
    }

    /// Raw request body bytes, as the host delivered them. Detectors
    /// prefer this over [`Request::body_text_lossy`] so non-UTF-8 payloads
    /// reach libinjection intact.
    pub fn body_bytes(&self) -> &[u8] {
        &self.body
    }

    /// Lossy UTF-8 preview of the body for audit-log serialization or
    /// debug output. Detectors should use [`Request::body_bytes`] (or
    /// [`Request::inspectable_fields`], which returns bytes).
    pub fn body_text_lossy(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }

    /// The original raw query string (verbatim, undecoded), if any.
    pub fn raw_query(&self) -> Option<&str> {
        self.raw_query.as_deref()
    }

    /// Every field a detector should scan, as **raw bytes**: the
    /// percent-decoded path, every decoded query-param value, the body
    /// (when `body_inspected`), and the value of every inspectable header
    /// (raw + percent-decoded forms; see `INSPECTABLE_HEADERS_EXACT`).
    ///
    /// Returning bytes (not `&str`) is deliberate — libinjection is byte-
    /// oriented and aho-corasick matches bytes natively. The lossy UTF-8
    /// conversion that used to happen on the body is gone, so a SQLi
    /// crafted in SHIFT-JIS or any non-UTF-8 encoding reaches the
    /// detector in its original bytes (NEW-I2 in the followup review).
    ///
    /// Headers are appended last so test/detector ordering stays stable
    /// for path/query/body assertions.
    pub fn inspectable_fields(&self) -> Vec<&[u8]> {
        let mut out: Vec<&[u8]> = vec![self.path.as_bytes()];
        for (_, v) in &self.query_params {
            out.push(v.as_bytes());
        }
        if self.body_inspected {
            out.push(self.body.as_slice());
        }
        out.extend(self.inspectable_headers.iter().map(Vec::as_slice));
        out
    }

    /// Values of headers in the inspection allow-list — both raw and
    /// percent-decoded forms, deduplicated. Pre-computed at `build` time.
    /// Detectors typically read these via [`Request::inspectable_fields`];
    /// this accessor exists for callers that need to distinguish header
    /// values from URL/body inputs (e.g. for severity or detail formatting).
    pub fn inspectable_header_values(&self) -> &[Vec<u8>] {
        &self.inspectable_headers
    }

    /// Look up a header by name. The lookup is case-insensitive regardless of
    /// the caller's casing.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The raw `User-Agent` header value, if present. Used by the injection
    /// detector's UA suffix probe (libinjection fingerprints a browser-
    /// prefixed UA as a UA string and misses trailing SQL).
    pub fn user_agent(&self) -> Option<&str> {
        self.header("user-agent")
    }
}

/// Maximum number of percent-decode passes applied to a single field.
///
/// A WAF must decode to a fixpoint: attackers double- and triple-encode
/// payloads (`%2527` → `%27` → `'`) precisely because single-pass decoders
/// inspect the still-encoded form and miss the cleartext attack. But an
/// unbounded "decode until stable" loop is itself a DoS primitive on a
/// crafted input, so we cap the passes. Three covers triple-encoding —
/// the observed ceiling for real-world evasion kits — while staying O(1)
/// per field.
///
/// This is inspection-only: the decoded form is never forwarded upstream,
/// so over-decoding can only raise inspection aggressiveness, never alter
/// the bytes the backend receives.
const MAX_DECODE_PASSES: usize = 3;

/// Percent-decode to a fixpoint (bounded), lossily. Applied so multiply-
/// encoded evasion payloads normalize to the cleartext detectors match on.
/// Stops early when a pass makes no change or no `%` remains.
fn decode(s: &str) -> String {
    let mut cur = percent_decode_str(s).decode_utf8_lossy().into_owned();
    for _ in 1..MAX_DECODE_PASSES {
        // Fixpoint: nothing left that could be a percent-escape.
        if !cur.contains('%') {
            break;
        }
        let next = percent_decode_str(&cur).decode_utf8_lossy().into_owned();
        // Fixpoint: this pass changed nothing (e.g. a lone `%` or `%zz`).
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Pre-compute the values of allow-listed headers in both raw and
/// percent-decoded form, as bytes (NEW-I2).
///
/// The decoded form closes a percent-encoded bypass of the header
/// inspection added in v0.2 C-1: without it, a payload like
/// `Cookie: id=%27%20OR%20%271%27%3D%271` would reach libinjection as
/// the literal `%27...` string and never match (NEW-I4 in the followup
/// review).
fn build_inspectable_headers(headers: &[(String, String)]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for (k, v) in headers {
        if INSPECTABLE_HEADERS_EXACT.contains(&k.as_str())
            || k.starts_with(INSPECTABLE_HEADER_PREFIX)
        {
            out.push(v.as_bytes().to_vec());
            let decoded = decode(v);
            if decoded != *v {
                out.push(decoded.into_bytes());
            }
        }
    }
    out
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
/// **Trust model (RFC 7239 §5.2):** `X-Forwarded-For` is a chain
/// `client, proxy1, proxy2, …` where each proxy *appends* the address it
/// observed. The **leftmost** entry is the client-asserted IP — the *least*
/// trustworthy hop, because any client behind a trusted edge can put
/// whatever it wants there. The **rightmost** entries are added by your own
/// infrastructure and are trustworthy to the degree you trust those proxies.
///
/// `trust_hops` is the number of *trusted* rightmost hops to peel off; the
/// returned IP is the leftmost untrusted-but-parseable entry after peeling
/// (i.e. the client as observed by your outermost trusted proxy). With
/// `trust_hops == 0` the function falls back directly to `peer`, which is
/// the only IP your wasm guest can actually verify.
///
/// Common settings:
/// - **0** (default) — you do not trust XFF at all. The reputation
///   detector keys on the TCP peer; XFF is ignored. Safe everywhere,
///   even on a tenant route directly exposed to the internet.
/// - **1** — one trusted proxy (Traefik) in front of the wasm guest.
///   This is the most common managed-platform shape.
/// - **N** — N trusted proxies (e.g. Cloudflare → ALB → Traefik = 2 or 3).
///
/// Misconfiguring this is a self-DoS / impersonation primitive: with too
/// high a value, attackers can put any IP they like in the leftmost XFF
/// slot and either pin per-IP rate-limit budgets to a victim's address or
/// rotate IPs to exhaust the rate-limiter's memory.
///
/// Resolution order: walk XFF after peeling `trust_hops` rightmost entries,
/// then fall through to `X-Real-IP` (matching the canonical Traefik
/// behavior), then to `peer`. Header lookup is case-insensitive. Malformed
/// values are skipped.
pub fn client_ip(headers: &[(String, String)], peer: IpAddr, trust_hops: usize) -> IpAddr {
    if trust_hops > 0 {
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("x-forwarded-for") {
                let parts: Vec<&str> = v.split(',').map(str::trim).collect();
                // Peel `trust_hops` rightmost entries; if we peel everything,
                // there's no untrusted hop left, so the request originated
                // *from* one of our trusted proxies — return `peer`.
                if parts.len() > trust_hops {
                    let cut = parts.len() - trust_hops;
                    for part in &parts[..cut] {
                        if let Ok(ip) = part.parse::<IpAddr>() {
                            return ip;
                        }
                    }
                }
            }
        }
        // Fall through to X-Real-IP — Traefik's canonical "real client" hint,
        // which it sets after applying its own trustedIPs configuration.
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("x-real-ip") {
                if let Ok(ip) = v.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    // trust_hops == 0, or peeling exhausted the chain: the only address
    // we can verify is the TCP peer.
    peer
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
    fn double_encoded_sqli_in_query_is_decoded() {
        // `%2527%2520OR%25201%253D1` is the double-encoding of
        // `%27%20OR%201%3D1`, which itself decodes to `' OR 1=1`. A
        // single-pass decoder leaves the inner `%27...` intact and the
        // payload sails past byte-oriented detectors. Decode-to-fixpoint
        // must recover the cleartext SQLi.
        let v = Request::build(
            "GET",
            "h",
            "/search",
            "q=%2527%2520OR%25201%253D1",
            vec![],
            vec![],
            false,
            ip(),
        );
        assert_eq!(
            v.query_params,
            vec![("q".to_string(), "' OR 1=1".to_string())]
        );
    }

    #[test]
    fn decode_is_bounded_and_stops_at_fixpoint() {
        // A value with no `%` is returned unchanged.
        assert_eq!(decode("plain-value"), "plain-value");
        // A lone `%` with no valid hex escape is stable: percent-encoding
        // leaves it as-is, so the loop detects the fixpoint and stops
        // rather than spinning.
        assert_eq!(decode("100%"), "100%");
        // A literal percent sign in benign content survives one decode and
        // is not mangled into something a detector would trip on.
        assert_eq!(decode("discount=50%25off"), "discount=50%off");
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
        assert!(!v.inspectable_fields().contains(&b"payload".as_slice()));
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
        assert!(v2.inspectable_fields().contains(&b"payload".as_slice()));
    }

    #[test]
    fn body_truncated_defaults_false_and_setter_flips_it() {
        let v = Request::build("POST", "h", "/p", "", vec![], b"abc".to_vec(), true, ip());
        assert!(!v.body_truncated, "body_truncated must default to false");
        let v2 = v.with_truncated_body(true);
        assert!(v2.body_truncated, "with_truncated_body(true) must set the flag");
    }

    #[test]
    fn truncated_body_prefix_is_still_inspected() {
        // When the body was truncated at the cap but we still inspect the
        // buffered prefix, the prefix bytes must appear in inspectable_fields
        // so an in-prefix payload is detected.
        let v = Request::build("POST", "h", "/p", "", vec![], b"prefix-bytes".to_vec(), true, ip())
            .with_truncated_body(true);
        assert!(v.inspectable_fields().contains(&b"prefix-bytes".as_slice()));
        assert!(v.body_truncated);
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
        assert!(fields.contains(&b"sess=abc; id=42".as_slice()));
        assert!(fields.contains(&b"https://x.example/from".as_slice()));
        assert!(fields.contains(&b"Bearer tok".as_slice()));
        assert!(fields.contains(&b"victor".as_slice()));
        assert!(fields.contains(&b"Mozilla/5.0".as_slice()));
        assert!(!fields.contains(&b"en-US".as_slice()));
        assert!(!fields.contains(&b"no-cache".as_slice()));
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
        // Values are bytes (NEW-I2); compare against byte slices.
        let values: Vec<&[u8]> = v
            .inspectable_header_values()
            .iter()
            .map(Vec::as_slice)
            .collect();
        assert_eq!(values, vec![b"1.2.3.4".as_slice()]);
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
        assert_eq!(
            v.inspectable_fields(),
            vec![
                b"/path".as_slice(),
                b"qv".as_slice(),
                b"body".as_slice(),
                b"ck".as_slice(),
            ]
        );
    }

    // ── client_ip tests (trust model — NEW-H3) ──────────────────────────────

    #[test]
    fn client_ip_with_trust_hops_zero_always_returns_peer() {
        // Even with a populated XFF, trust_hops=0 means "I do not trust XFF".
        // This is the safe default: any tenant route exposed to the
        // internet without an explicit `trustedHops` setting cannot be
        // self-DoS'd via spoofed XFF.
        let h = vec![(
            "x-forwarded-for".to_string(),
            "203.0.113.7, 10.0.0.1".to_string(),
        )];
        assert_eq!(client_ip(&h, peer(), 0), peer());
    }

    #[test]
    fn client_ip_with_one_trusted_hop_peels_rightmost() {
        // Chain: client(203.0.113.7), trusted-edge(10.0.0.1). trust_hops=1
        // peels the trusted-edge entry; the client-asserted IP wins.
        let h = vec![(
            "x-forwarded-for".to_string(),
            "203.0.113.7, 10.0.0.1".to_string(),
        )];
        assert_eq!(
            client_ip(&h, peer(), 1),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_with_two_trusted_hops_peels_two_rightmost() {
        // Chain: client, cloudflare-edge, alb. trust_hops=2 peels both edges.
        let h = vec![(
            "x-forwarded-for".to_string(),
            "203.0.113.7, 10.0.0.1, 10.0.0.2".to_string(),
        )];
        assert_eq!(
            client_ip(&h, peer(), 2),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_when_trust_exhausts_chain_returns_peer() {
        // Chain has 1 entry, trust_hops says 3 are trusted — the request
        // came directly from one of our trusted proxies (no client hop in
        // the chain). Returning peer is the only honest answer.
        let h = vec![("x-forwarded-for".to_string(), "10.0.0.1".to_string())];
        assert_eq!(client_ip(&h, peer(), 3), peer());
    }

    #[test]
    fn client_ip_falls_through_garbage_after_peeling() {
        // After peeling the rightmost trusted hop, the next-leftmost is
        // garbage; we fall through to the next parseable entry.
        let h = vec![(
            "x-forwarded-for".to_string(),
            "not-an-ip, 198.51.100.5, 10.0.0.1".to_string(),
        )];
        assert_eq!(
            client_ip(&h, peer(), 1),
            "198.51.100.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_uses_x_real_ip_when_xff_absent_and_hops_set() {
        // Traefik strips XFF and sets X-Real-IP after applying its own
        // trustedIPs configuration; respect it when trust_hops > 0.
        let h = vec![("x-real-ip".to_string(), "198.51.100.9".to_string())];
        assert_eq!(
            client_ip(&h, peer(), 1),
            "198.51.100.9".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_ignores_x_real_ip_when_hops_zero() {
        // X-Real-IP is also part of the XFF-trust chain — without explicit
        // opt-in, we don't trust it either.
        let h = vec![("x-real-ip".to_string(), "198.51.100.9".to_string())];
        assert_eq!(client_ip(&h, peer(), 0), peer());
    }

    #[test]
    fn client_ip_falls_back_to_peer_when_both_unparseable() {
        let h = vec![
            ("x-forwarded-for".to_string(), "not-an-ip".to_string()),
            ("x-real-ip".to_string(), "also-not".to_string()),
        ];
        assert_eq!(client_ip(&h, peer(), 1), peer());
    }
}
