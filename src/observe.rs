use crate::policy::{Action, Decision};
use crate::request_model::RequestView;
use serde::Serialize;

/// One audit-log line. Emitted for any request with verdicts.
#[derive(Debug, Serialize, PartialEq)]
pub struct AuditEntry {
    pub host: String,
    pub path: String,
    /// Raw query string (verbatim), if any. Preserved so the audit log shows
    /// the attack payload's location when it sits in query params.
    pub query: Option<String>,
    pub method: String,
    pub source_ip: String,
    pub action: String,
    pub blocked_rule: Option<String>,
    /// Severity of the blocking verdict, if any (e.g. "high", "critical").
    pub blocked_severity: Option<String>,
    /// Free-form detail from the blocking verdict, if any.
    pub blocked_detail: Option<String>,
    pub would_block_rules: Vec<String>,
}

impl AuditEntry {
    pub fn from(req: &RequestView, decision: &Decision) -> AuditEntry {
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
            blocked_rule: decision.blocked_by.as_ref().map(|v| {
                format!("{}/{}", v.group.as_str(), v.rule)
            }),
            blocked_severity: decision
                .blocked_by
                .as_ref()
                .map(|v| v.severity.as_str().to_string()),
            blocked_detail: decision
                .blocked_by
                .as_ref()
                .map(|v| v.detail.clone()),
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

/// Record Prometheus counters/histogram for one handled request.
pub fn record_request(action: Action, group_hits: &[&str], latency_us: f64) {
    metrics::counter!("purple_wolf_requests_total").increment(1);
    match action {
        Action::Allow => metrics::counter!("purple_wolf_allowed_total").increment(1),
        Action::Block => metrics::counter!("purple_wolf_blocked_total").increment(1),
    }
    for g in group_hits {
        metrics::counter!("purple_wolf_group_hits_total", "group" => g.to_string()).increment(1);
    }
    metrics::histogram!("purple_wolf_added_latency_us").record(latency_us);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::{Group, Severity, Verdict};
    use std::net::IpAddr;

    fn req() -> RequestView {
        RequestView::build("GET", "Host", "/p", "", vec![], vec![], false,
            "1.2.3.4".parse::<IpAddr>().unwrap())
    }

    fn req_with_query(q: &str) -> RequestView {
        RequestView::build("GET", "Host", "/p", q, vec![], vec![], false,
            "1.2.3.4".parse::<IpAddr>().unwrap())
    }

    #[test]
    fn audit_entry_records_block() {
        let decision = Decision {
            action: Action::Block,
            blocked_by: Some(Verdict {
                group: Group::Injection, rule: "sqli",
                severity: Severity::Critical, detail: "d".into(),
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
                group: Group::Injection, rule: "sqli",
                severity: Severity::High, detail: "payload in q".into(),
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
        let decision = Decision { action: Action::Allow, blocked_by: None, would_block: vec![] };
        let entry = AuditEntry::from(&req(), &decision);
        assert!(!entry.is_noteworthy());
        assert_eq!(entry.blocked_severity, None);
        assert_eq!(entry.blocked_detail, None);
    }
}
