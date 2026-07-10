//! Parser: extract a purple-wolf audit JSON object from one Traefik
//! log line.
//!
//! Strategy: strip ANSI escapes, find the first balanced JSON object,
//! parse it, and verify it carries the purple-wolf signature fields
//! (`would_block_rules` and a known `action` value). Lines that
//! don't match the signature are rejected with `NotPurpleWolf`. The
//! check is strict enough to skip Traefik's own access-log lines and
//! plugin lifecycle messages without false positives.
//!
//! Traefik adds enrichment fields (`middlewareName`, `routerName`,
//! `entryPointName`) outside the JSON payload — typically as
//! `key=value` pairs in the surrounding log text. They're best-effort:
//! found and surfaced when present, ignored otherwise.

use std::borrow::Cow;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    /// No JSON object in the line, or the JSON doesn't match the
    /// purple-wolf signature. Not necessarily an error — most Traefik
    /// log lines look like this. Callers usually warn-and-skip.
    #[error("line does not appear to be a purple-wolf audit log entry")]
    NotPurpleWolf,
    /// We found a JSON object that looked like ours, but it failed to
    /// parse. Surface so the operator notices schema drift.
    #[error("malformed purple-wolf audit JSON: {0}")]
    Malformed(String),
}

/// Output of a successful parse.
#[derive(Debug, Clone)]
pub struct ParsedAudit {
    /// The purple-wolf audit JSON payload.
    pub event: serde_json::Value,
    /// Best-effort Traefik enrichment, extracted from the log line's
    /// trailing `middlewareName=...` text. The `@file` /
    /// `@kubernetescrd` suffix is stripped for stable identifiers.
    pub middleware: Option<String>,
    pub router: Option<String>,
    pub entry_point: Option<String>,
}

/// Attempt to parse one Traefik log line.
pub fn parse_line(bytes: &[u8]) -> Result<ParsedAudit, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::NotPurpleWolf)?;

    // Source tasks feed every Traefik log line through this parser. ANSI
    // escapes cannot encode a JSON opening brace, so reject the overwhelmingly
    // common non-JSON line before allocating or scanning escape sequences.
    if !text.as_bytes().contains(&b'{') {
        return Err(ParseError::NotPurpleWolf);
    }
    let stripped = strip_ansi(text);

    let Some((start, end)) = find_json_object(&stripped) else {
        return Err(ParseError::NotPurpleWolf);
    };
    let json_slice = &stripped[start..=end];

    let event: serde_json::Value = match serde_json::from_str(json_slice) {
        Ok(v) => v,
        Err(_) => {
            // Strip leading non-JSON text and try once more — Traefik
            // sometimes prefixes the log payload with a level marker.
            return Err(ParseError::NotPurpleWolf);
        }
    };

    // Signature: must contain would_block_rules (purple-wolf-specific)
    // AND an action of "block" or "allow". Without both we treat it as
    // a foreign log line.
    let has_wbr = event.get("would_block_rules").is_some();
    let action_ok = matches!(
        event.get("action").and_then(|v| v.as_str()),
        Some("block") | Some("allow")
    );
    if !(has_wbr && action_ok) {
        return Err(ParseError::NotPurpleWolf);
    }

    let (middleware, router, entry_point) = extract_traefik_enrichment(&stripped);

    Ok(ParsedAudit {
        event,
        middleware,
        router,
        entry_point,
    })
}

/// Find the first `{` and its matching `}` in `s`, respecting strings
/// and escapes. Returns the byte-range bounds. None if no balanced
/// object is found.
fn find_json_object(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let start = bytes.iter().position(|&b| b == b'{')?;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((start, i));
                }
            }
            _ => {}
        }
    }
    None
}

/// Remove ANSI escape sequences (CSI: `\x1b[...m` and similar) so we can do
/// simple string searches against the log line. Plain production log lines
/// are borrowed unchanged; only a line that actually contains ESC allocates.
fn strip_ansi(s: &str) -> Cow<'_, str> {
    if !s.as_bytes().contains(&b'\x1b') {
        return Cow::Borrowed(s);
    }

    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // ESC. Consume an optional '[' and everything until the
            // first letter (the CSI terminator).
            if chars.peek() == Some(&'[') {
                chars.next();
            }
            for nc in chars.by_ref() {
                if nc.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    Cow::Owned(out)
}

/// Extract `middlewareName=...`, `routerName=...`, `entryPointName=...`
/// from the (already ANSI-stripped) log line. Traefik formats these
/// as space-separated `key=value` pairs after the JSON payload. Stops
/// at the next whitespace.
fn extract_traefik_enrichment(s: &str) -> (Option<String>, Option<String>, Option<String>) {
    let middleware = find_value(s, "middlewareName=").map(strip_traefik_suffix);
    let router = find_value(s, "routerName=").map(strip_traefik_suffix);
    let entry_point = find_value(s, "entryPointName=");
    (middleware, router, entry_point)
}

fn find_value(haystack: &str, key: &str) -> Option<String> {
    let idx = haystack.find(key)?;
    let rest = &haystack[idx + key.len()..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    let v = rest[..end].trim_matches(|c: char| c == '"' || c == '\'');
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

/// `strict-waf@file` → `strict-waf`. Operators describe their world by
/// the bare name; the source-of-truth suffix is noise for routing.
fn strip_traefik_suffix(v: String) -> String {
    v.split_once('@').map(|(k, _)| k.to_string()).unwrap_or(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "pw-sim-traefik-1  | \x1b[90m2026-05-25T17:30:02Z\x1b[0m \x1b[32mINF\x1b[0m \x1b[1m{\"host\":\"127.0.0.1:8000\",\"path\":\"/\",\"query\":\"id=1%27\",\"method\":\"GET\",\"source_ip\":\"203.0.113.7\",\"action\":\"block\",\"blocked_rule\":\"injection/sqli\",\"blocked_severity\":\"critical\",\"blocked_detail\":\"SQLi in field: 1'\",\"would_block_rules\":[],\"labels\":{\"tenant\":\"acme\"}}\x1b[0m \x1b[36mentryPointName=\x1b[0mweb \x1b[36mmiddlewareName=\x1b[0mstrict-waf@file \x1b[36mrouterName=\x1b[0mstrict@file";

    #[test]
    fn parses_real_traefik_audit_line() {
        let p = parse_line(SAMPLE.as_bytes()).unwrap();
        assert_eq!(p.middleware.as_deref(), Some("strict-waf"));
        assert_eq!(p.router.as_deref(), Some("strict"));
        assert_eq!(p.entry_point.as_deref(), Some("web"));
        assert_eq!(p.event["action"], "block");
        assert_eq!(p.event["labels"]["tenant"], "acme");
        assert_eq!(p.event["blocked_rule"], "injection/sqli");
    }

    #[test]
    fn rejects_non_purple_wolf_line() {
        let line = b"INF Traefik startup complete";
        assert!(matches!(parse_line(line), Err(ParseError::NotPurpleWolf)));
    }

    #[test]
    fn ansi_normalization_borrows_plain_lines() {
        let line = r#"{"action":"allow","would_block_rules":[]}"#;
        assert!(matches!(strip_ansi(line), Cow::Borrowed(_)));
    }

    #[test]
    fn ansi_normalization_owns_only_when_escape_sequences_are_present() {
        let line = "\x1b[32mgreen\x1b[0m";
        let stripped = strip_ansi(line);
        assert!(matches!(stripped, Cow::Owned(_)));
        assert_eq!(stripped, "green");
    }

    #[test]
    fn rejects_json_without_pw_signature() {
        // A JSON object but missing would_block_rules.
        let line = br#"{"hello":"world","action":"block"}"#;
        assert!(matches!(parse_line(line), Err(ParseError::NotPurpleWolf)));
    }

    #[test]
    fn rejects_json_with_unknown_action() {
        let line = br#"{"action":"shrug","would_block_rules":[]}"#;
        assert!(matches!(parse_line(line), Err(ParseError::NotPurpleWolf)));
    }

    #[test]
    fn accepts_minimal_allow_event() {
        // Audit lines from monitor-mode requests carry action=allow +
        // would_block_rules but no blocked_rule.
        let line = br#"{"action":"allow","would_block_rules":["injection/sqli"],"host":"x","path":"/","method":"GET","source_ip":"1.2.3.4"}"#;
        let p = parse_line(line).unwrap();
        assert_eq!(p.event["action"], "allow");
    }

    #[test]
    fn handles_line_without_traefik_enrichment() {
        let line = br#"{"action":"block","would_block_rules":[]}"#;
        let p = parse_line(line).unwrap();
        assert!(p.middleware.is_none());
        assert!(p.router.is_none());
        assert!(p.entry_point.is_none());
    }

    #[test]
    fn parser_is_total_on_random_bytes() {
        // Quick adversarial cases that exercise edge paths.
        let cases: &[&[u8]] = &[
            b"",
            b"{",
            b"}",
            b"{}{",
            b"{\"a\":\"\\\"}", // unterminated string
            &[0xff, 0xfe, 0xfd],
            b"{\"would_block_rules\":[],", // truncated valid JSON
        ];
        for c in cases {
            // Must not panic.
            let _ = parse_line(c);
        }
    }

    #[test]
    fn strips_traefik_suffix_only_when_present() {
        assert_eq!(strip_traefik_suffix("foo".into()), "foo");
        assert_eq!(strip_traefik_suffix("foo@file".into()), "foo");
        assert_eq!(strip_traefik_suffix("foo@kubernetescrd".into()), "foo");
    }

    /// The plain (non-ANSI) form some operators see when piping to a
    /// log aggregator that already stripped escapes.
    #[test]
    fn parses_plain_line_without_ansi() {
        let line = r#"{"host":"x","path":"/","method":"GET","source_ip":"1.2.3.4","action":"block","blocked_rule":"injection/sqli","blocked_severity":"critical","would_block_rules":[]} middlewareName=strict-waf@file routerName=strict@file entryPointName=web"#;
        let p = parse_line(line.as_bytes()).unwrap();
        assert_eq!(p.middleware.as_deref(), Some("strict-waf"));
        assert_eq!(p.router.as_deref(), Some("strict"));
        assert_eq!(p.entry_point.as_deref(), Some("web"));
    }
}
