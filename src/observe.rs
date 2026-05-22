use crate::policy::{Action, Decision};
use crate::request_model::RequestView;
use serde::Serialize;

/// One audit-log line. Emitted for any request with verdicts.
#[derive(Debug, Serialize, PartialEq)]
pub struct AuditEntry {
    pub host: String,
    pub path: String,
    pub method: String,
    pub source_ip: String,
    pub action: String,
    pub blocked_rule: Option<String>,
    pub would_block_rules: Vec<String>,
}

impl AuditEntry {
    pub fn from(req: &RequestView, decision: &Decision) -> AuditEntry {
        AuditEntry {
            host: req.host.clone(),
            path: req.path.clone(),
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
        assert!(entry.is_noteworthy());
    }

    #[test]
    fn clean_request_is_not_noteworthy() {
        let decision = Decision { action: Action::Allow, blocked_by: None, would_block: vec![] };
        assert!(!AuditEntry::from(&req(), &decision).is_noteworthy());
    }
}
