//! Audit-log types and serialization helpers.
use crate::policy::{Action, Decision};
use crate::request::Request;
use serde::Serialize;
use std::collections::BTreeMap;

/// One audit-log line. Emitted for any request with verdicts.
#[derive(Debug, Serialize, PartialEq)]
pub struct AuditEntry {
    /// Lowercased hostname from the request.
    pub host: String,
    /// Request path as received.
    pub path: String,
    /// Raw query string (verbatim), if any. Preserved so the audit log shows
    /// the attack payload's location when it sits in query params.
    pub query: Option<String>,
    /// HTTP method, upper-cased.
    pub method: String,
    /// Source IP address as a string.
    pub source_ip: String,
    /// Final action taken: `"allow"` or `"block"`.
    pub action: String,
    /// Identifier of the rule that caused a block, if any.
    pub blocked_rule: Option<String>,
    /// Severity of the blocking verdict, if any (e.g. "high", "critical").
    pub blocked_severity: Option<String>,
    /// Free-form detail from the blocking verdict, if any.
    pub blocked_detail: Option<String>,
    /// Rules that would have blocked but were not enforced.
    pub would_block_rules: Vec<String>,
    /// Whether the request body exceeded the inspection cap and only its
    /// buffered prefix was inspected (bytes past the cap went un-inspected).
    /// `skip_serializing_if` keeps the v0.2 audit-log shape unchanged for the
    /// common, non-truncated case — the field appears only when `true`.
    #[serde(skip_serializing_if = "is_false")]
    pub body_truncated: bool,
    /// Operator-supplied labels from `Config.labels`. Emitted verbatim
    /// (with control characters scrubbed) so downstream relays /
    /// log pipelines can route on them. `skip_serializing_if` keeps the
    /// audit-log shape unchanged for v0.2 Middlewares that don't set
    /// labels — minimum churn for existing log queries.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl AuditEntry {
    /// Build an `AuditEntry` from a request and the corresponding decision.
    /// No labels are attached; preserved for v0.2 callers and tests.
    pub fn from(req: &Request, decision: &Decision) -> AuditEntry {
        Self::from_with_labels(req, decision, &BTreeMap::new())
    }

    /// Build an `AuditEntry` carrying the operator's labels. Label values
    /// are scrubbed of ASCII control characters at emit time — labels are
    /// operator-set, but treating them as opaque means an unsafe value
    /// (CR/LF/etc.) injected via the config plane can never reach the
    /// audit log verbatim. Same hardening as `blocked_detail`.
    pub fn from_with_labels(
        req: &Request,
        decision: &Decision,
        labels: &BTreeMap<String, String>,
    ) -> AuditEntry {
        AuditEntry {
            host: req.host.clone(),
            path: req.path.clone(),
            query: req.raw_query().map(|s| s.to_string()),
            method: req.method.clone(),
            source_ip: req.source_ip.to_string(),
            action: match decision.action {
                Action::Allow => "allow",
                Action::Block => "block",
            }
            .to_string(),
            blocked_rule: decision
                .blocked_by
                .as_ref()
                .map(|v| format!("{}/{}", v.group.as_str(), v.rule)),
            blocked_severity: decision
                .blocked_by
                .as_ref()
                .map(|v| v.severity.as_str().to_string()),
            blocked_detail: decision.blocked_by.as_ref().map(|v| v.detail.clone()),
            would_block_rules: decision
                .would_block
                .iter()
                .map(|v| format!("{}/{}", v.group.as_str(), v.rule))
                .collect(),
            body_truncated: req.body_truncated,
            labels: labels
                .iter()
                .map(|(k, v)| (k.clone(), scrub_label_value(v)))
                .collect(),
        }
    }

    /// True if there is anything worth logging.
    pub fn is_noteworthy(&self) -> bool {
        self.blocked_rule.is_some() || !self.would_block_rules.is_empty()
    }
}

/// Strip ASCII control characters (`\x00..=\x1F`, `\x7F`) from a label
/// value before it lands in the audit log. Mirrors the log-injection
/// guard applied to `blocked_detail`: a control character in a label
/// value could otherwise let an operator (or a tenant-controlled config
/// upstream of the operator) break the per-line JSON shape downstream
/// log pipelines depend on.
fn scrub_label_value(v: &str) -> String {
    v.chars()
        .map(|c| {
            if (c as u32) < 0x20 || c == '\x7f' {
                '.'
            } else {
                c
            }
        })
        .collect()
}

/// Predicate for `#[serde(skip_serializing_if)]` on `bool` fields — keeps
/// additive audit fields out of the JSON in their default (false) state so
/// the v0.2 log shape is preserved for the common case.
fn is_false(b: &bool) -> bool {
    !*b
}

/// Serialize an AuditEntry as a single-line JSON string suitable for
/// emission via the deployment's logging mechanism (host `log()` in WASM,
/// stdout in a native deployment).
pub fn to_log_line(entry: &AuditEntry) -> String {
    serde_json::to_string(entry)
        .unwrap_or_else(|_| String::from("{\"error\":\"audit serialize failed\"}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::{Group, Severity, Verdict};
    use std::net::IpAddr;

    fn req() -> Request {
        Request::build(
            "GET",
            "Host",
            "/p",
            "",
            vec![],
            vec![],
            false,
            "1.2.3.4".parse::<IpAddr>().unwrap(),
        )
    }

    fn req_with_query(q: &str) -> Request {
        Request::build(
            "GET",
            "Host",
            "/p",
            q,
            vec![],
            vec![],
            false,
            "1.2.3.4".parse::<IpAddr>().unwrap(),
        )
    }

    #[test]
    fn audit_entry_records_block() {
        let decision = Decision {
            action: Action::Block,
            blocked_by: Some(Verdict {
                group: Group::Injection,
                rule: "sqli",
                severity: Severity::Critical,
                detail: "d".into(),
            }),
            would_block: vec![],
        };
        let entry = AuditEntry::from(&req(), &decision);
        assert_eq!(entry.action, "block");
        assert_eq!(entry.blocked_rule.as_deref(), Some("injection/sqli"));
        assert_eq!(entry.blocked_severity.as_deref(), Some("critical"));
        assert_eq!(entry.blocked_detail.as_deref(), Some("d"));
        assert_eq!(entry.query, None);
        assert!(entry.is_noteworthy());
    }

    #[test]
    fn audit_entry_preserves_raw_query() {
        let decision = Decision {
            action: Action::Block,
            blocked_by: Some(Verdict {
                group: Group::Injection,
                rule: "sqli",
                severity: Severity::High,
                detail: "payload in q".into(),
            }),
            would_block: vec![],
        };
        let entry = AuditEntry::from(&req_with_query("q=%27%20OR%201%3D1"), &decision);
        assert_eq!(entry.query.as_deref(), Some("q=%27%20OR%201%3D1"));
        assert_eq!(entry.blocked_severity.as_deref(), Some("high"));
        assert_eq!(entry.blocked_detail.as_deref(), Some("payload in q"));
    }

    #[test]
    fn clean_request_is_not_noteworthy() {
        let decision = Decision {
            action: Action::Allow,
            blocked_by: None,
            would_block: vec![],
        };
        let entry = AuditEntry::from(&req(), &decision);
        assert!(!entry.is_noteworthy());
        assert_eq!(entry.blocked_severity, None);
        assert_eq!(entry.blocked_detail, None);
        assert!(entry.labels.is_empty());
    }

    // ----- v0.3 labels -----

    fn block_decision() -> Decision {
        Decision {
            action: Action::Block,
            blocked_by: Some(Verdict {
                group: Group::Injection,
                rule: "sqli",
                severity: Severity::Critical,
                detail: "d".into(),
            }),
            would_block: vec![],
        }
    }

    #[test]
    fn audit_entry_includes_labels_when_present() {
        let labels = std::collections::BTreeMap::from([
            ("tenant".into(), "acme".into()),
            ("service".into(), "checkout".into()),
        ]);
        let entry = AuditEntry::from_with_labels(&req(), &block_decision(), &labels);
        let json = to_log_line(&entry);
        // BTreeMap iteration is alphabetical → keys in stable order.
        assert!(
            json.contains(r#""labels":{"service":"checkout","tenant":"acme"}"#),
            "json: {json}"
        );
    }

    #[test]
    fn audit_entry_omits_labels_field_when_empty_for_v02_backcompat() {
        let entry = AuditEntry::from_with_labels(
            &req(),
            &block_decision(),
            &std::collections::BTreeMap::new(),
        );
        let json = to_log_line(&entry);
        assert!(
            !json.contains("\"labels\""),
            "expected no labels field in {json}"
        );
    }

    #[test]
    fn audit_entry_scrubs_control_chars_in_label_values() {
        // A tenant sets a label value containing CR/LF + a fake JSON
        // fragment — must not survive into the audit JSON. This is the
        // labels-equivalent of the NEW-I1 log-injection guard applied
        // to `blocked_detail`.
        let labels = std::collections::BTreeMap::from([(
            "note".into(),
            "line1\r\n\"injected\":true,".into(),
        )]);
        let entry = AuditEntry::from_with_labels(&req(), &block_decision(), &labels);
        let json = to_log_line(&entry);
        assert!(!json.contains('\r'), "CR must be scrubbed: {json}");
        assert!(!json.contains('\n'), "LF must be scrubbed: {json}");
        // The injected-looking text survives as a single labels value
        // (now with control chars → '.') — but it's quoted inside the
        // labels value, so it can't escape the labels object.
        // The scrubbed substitution character is '.', so CR/LF → '..'.
        let entry_v = entry.labels.get("note").unwrap();
        assert!(entry_v.starts_with("line1.."), "scrubbed value: {entry_v}");
    }

    #[test]
    fn audit_entry_scrubs_del_char_in_label_values() {
        let labels = std::collections::BTreeMap::from([("k".into(), "a\x7fb".into())]);
        let entry = AuditEntry::from_with_labels(&req(), &block_decision(), &labels);
        assert_eq!(entry.labels.get("k").map(String::as_str), Some("a.b"));
    }

    // ── body_truncated audit field (Tier 1.6) ───────────────────────────────

    #[test]
    fn audit_marks_body_truncated_when_request_body_was_truncated() {
        let truncated_req = Request::build(
            "POST",
            "Host",
            "/p",
            "",
            vec![],
            b"prefix".to_vec(),
            true,
            "1.2.3.4".parse::<IpAddr>().unwrap(),
        )
        .with_truncated_body(true);
        let entry = AuditEntry::from(&truncated_req, &block_decision());
        assert!(entry.body_truncated, "entry must carry body_truncated");
        let json = to_log_line(&entry);
        assert!(
            json.contains(r#""body_truncated":true"#),
            "json must include body_truncated when set: {json}"
        );
    }

    #[test]
    fn audit_omits_body_truncated_when_false_for_v02_backcompat() {
        // Default (non-truncated) requests must not carry the field, so the
        // v0.2 audit-log shape is unchanged for the common case.
        let entry = AuditEntry::from(&req(), &block_decision());
        assert!(!entry.body_truncated);
        let json = to_log_line(&entry);
        assert!(
            !json.contains("body_truncated"),
            "field must be omitted when false: {json}"
        );
    }
}
