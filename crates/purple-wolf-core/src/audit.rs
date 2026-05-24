//! Audit-log types and serialization helpers.
use crate::policy::{Action, Decision};
use crate::request::Request;
use serde::Serialize;

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
}

impl AuditEntry {
    /// Build an `AuditEntry` from a request and the corresponding decision.
    pub fn from(req: &Request, decision: &Decision) -> AuditEntry {
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
        }
    }

    /// True if there is anything worth logging.
    pub fn is_noteworthy(&self) -> bool {
        self.blocked_rule.is_some() || !self.would_block_rules.is_empty()
    }
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
    }
}
