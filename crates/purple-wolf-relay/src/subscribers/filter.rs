//! Compiled subscriber filter predicate.
//!
//! `SubscriberFilter` from config is opaque to the rest of the
//! pipeline; this module turns it into a `CompiledFilter` whose
//! `matches(&Envelope)` is the hot path.
//!
//! Semantics (mirroring docs/webhook-protocol.md):
//!
//! - `labels`: every `(k, v)` pair in the filter must appear in the
//!   envelope's labels with the same value.
//! - `severity_min`: `envelope.event["blocked_severity"]` must parse
//!   as a known `Severity` and be `>= severity_min`. If
//!   `blocked_severity` is absent the event is dropped (rule-only
//!   `would_block_rules` entries don't carry severity in the audit schema).
//! - `blocked_rule_pattern`: simple glob (`*` wildcard) against
//!   `event["blocked_rule"]` OR any entry of
//!   `event["would_block_rules"]`.
//!
//! An empty filter (no clauses) matches every envelope.

use crate::config::{Severity, SubscriberFilter};
use crate::envelope::Envelope;

#[derive(Debug)]
pub struct CompiledFilter {
    labels: std::collections::BTreeMap<String, String>,
    severity_min: Option<Severity>,
    rule_glob: Option<Glob>,
}

impl CompiledFilter {
    pub fn compile(f: &SubscriberFilter) -> Self {
        Self {
            labels: f.labels.clone(),
            severity_min: f.severity_min,
            rule_glob: f.blocked_rule_pattern.as_deref().map(Glob::new),
        }
    }

    /// True if the envelope satisfies every filter clause.
    pub fn matches(&self, env: &Envelope) -> bool {
        // labels: filter must be a subset of envelope labels.
        for (k, v) in &self.labels {
            if env.labels.get(k) != Some(v) {
                return false;
            }
        }

        // severity_min.
        if let Some(min) = self.severity_min {
            let event_severity = env
                .event
                .get("blocked_severity")
                .and_then(|v| v.as_str())
                .and_then(parse_severity);
            match event_severity {
                Some(sev) if sev >= min => {}
                _ => return false,
            }
        }

        // blocked_rule_pattern.
        if let Some(g) = &self.rule_glob {
            let direct = env
                .event
                .get("blocked_rule")
                .and_then(|v| v.as_str())
                .map(|s| g.matches(s))
                .unwrap_or(false);
            if direct {
                return true; // already passed earlier clauses
            }
            let would = env
                .event
                .get("would_block_rules")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str()).any(|s| g.matches(s)))
                .unwrap_or(false);
            if !would {
                return false;
            }
        }
        true
    }
}

fn parse_severity(s: &str) -> Option<Severity> {
    match s {
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// Tiny glob matcher supporting only `*` (zero-or-more wildcard).
/// Faster than dragging in a regex / glob crate for one symbol.
#[derive(Debug, Clone)]
pub struct Glob {
    parts: Vec<String>,
    starts_wild: bool,
    ends_wild: bool,
}

impl Glob {
    pub fn new(pattern: &str) -> Self {
        let starts_wild = pattern.starts_with('*');
        let ends_wild = pattern.ends_with('*');
        let parts: Vec<String> = pattern
            .split('*')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        Self {
            parts,
            starts_wild,
            ends_wild,
        }
    }

    pub fn matches(&self, s: &str) -> bool {
        if self.parts.is_empty() {
            // Pattern was "" or only stars.
            return true;
        }
        let mut cursor = 0usize;
        // Anchor first part if pattern doesn't start with *.
        let (first, rest) = self.parts.split_first().unwrap();
        if self.starts_wild {
            match s[cursor..].find(first.as_str()) {
                Some(idx) => cursor += idx + first.len(),
                None => return false,
            }
        } else {
            if !s.starts_with(first.as_str()) {
                return false;
            }
            cursor += first.len();
        }
        // Middle parts: must appear in order.
        let last_idx = rest.len().saturating_sub(1);
        for (i, part) in rest.iter().enumerate() {
            let is_last = i == last_idx;
            let anchor_end = is_last && !self.ends_wild;
            if anchor_end {
                if !s[cursor..].ends_with(part.as_str()) {
                    return false;
                }
                // Make sure the remaining suffix is exactly this part.
                let want = s.len().saturating_sub(part.len());
                if want < cursor {
                    return false;
                }
                cursor = s.len();
            } else {
                match s[cursor..].find(part.as_str()) {
                    Some(idx) => cursor += idx + part.len(),
                    None => return false,
                }
            }
        }
        if !self.ends_wild && cursor != s.len() {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, EnvelopeSource};
    use std::collections::BTreeMap;

    fn env_with(labels: BTreeMap<String, String>, event: serde_json::Value) -> Envelope {
        Envelope::new(
            event,
            EnvelopeSource {
                middleware: None,
                router: None,
                entry_point: None,
                relay_instance: "r1".into(),
            },
            labels,
        )
    }

    fn block_event(rule: &str, severity: &str) -> serde_json::Value {
        serde_json::json!({
            "action": "block",
            "blocked_rule": rule,
            "blocked_severity": severity,
            "would_block_rules": []
        })
    }

    #[test]
    fn empty_filter_matches_everything() {
        let f = CompiledFilter::compile(&SubscriberFilter::default());
        let env = env_with(BTreeMap::new(), serde_json::json!({}));
        assert!(f.matches(&env));
    }

    #[test]
    fn labels_filter_requires_subset_match() {
        let f = CompiledFilter::compile(&SubscriberFilter {
            labels: BTreeMap::from([("tenant".into(), "acme".into())]),
            ..Default::default()
        });
        // Match: envelope has the required label.
        let env = env_with(
            BTreeMap::from([
                ("tenant".into(), "acme".into()),
                ("region".into(), "us-east-1".into()),
            ]),
            serde_json::json!({}),
        );
        assert!(f.matches(&env));
        // Miss: wrong value.
        let env = env_with(
            BTreeMap::from([("tenant".into(), "contoso".into())]),
            serde_json::json!({}),
        );
        assert!(!f.matches(&env));
        // Miss: missing key.
        let env = env_with(BTreeMap::new(), serde_json::json!({}));
        assert!(!f.matches(&env));
    }

    #[test]
    fn severity_filter_rejects_below_floor() {
        let f = CompiledFilter::compile(&SubscriberFilter {
            severity_min: Some(Severity::High),
            ..Default::default()
        });
        assert!(!f.matches(&env_with(
            BTreeMap::new(),
            block_event("injection/sqli", "medium")
        )));
        assert!(f.matches(&env_with(
            BTreeMap::new(),
            block_event("injection/sqli", "high")
        )));
        assert!(f.matches(&env_with(
            BTreeMap::new(),
            block_event("injection/sqli", "critical")
        )));
    }

    #[test]
    fn severity_filter_rejects_when_severity_missing() {
        let f = CompiledFilter::compile(&SubscriberFilter {
            severity_min: Some(Severity::Low),
            ..Default::default()
        });
        // Allow-mode events don't have blocked_severity; severity_min
        // can't be satisfied on them.
        let env = env_with(
            BTreeMap::new(),
            serde_json::json!({"action": "allow", "would_block_rules": []}),
        );
        assert!(!f.matches(&env));
    }

    #[test]
    fn rule_pattern_matches_blocked_rule() {
        let f = CompiledFilter::compile(&SubscriberFilter {
            blocked_rule_pattern: Some("injection/*".into()),
            ..Default::default()
        });
        assert!(f.matches(&env_with(
            BTreeMap::new(),
            block_event("injection/sqli", "high")
        )));
        assert!(!f.matches(&env_with(
            BTreeMap::new(),
            block_event("reputation/deny", "high")
        )));
    }

    #[test]
    fn rule_pattern_falls_back_to_would_block_rules() {
        // Monitor-mode event: no blocked_rule, but would_block_rules
        // contains a matching entry.
        let f = CompiledFilter::compile(&SubscriberFilter {
            blocked_rule_pattern: Some("injection/*".into()),
            ..Default::default()
        });
        let env = env_with(
            BTreeMap::new(),
            serde_json::json!({
                "action": "allow",
                "would_block_rules": ["injection/sqli", "structural/header"]
            }),
        );
        assert!(f.matches(&env));
    }

    #[test]
    fn all_clauses_must_match() {
        let f = CompiledFilter::compile(&SubscriberFilter {
            labels: BTreeMap::from([("tenant".into(), "acme".into())]),
            severity_min: Some(Severity::Critical),
            blocked_rule_pattern: Some("injection/*".into()),
        });
        // Match.
        assert!(f.matches(&env_with(
            BTreeMap::from([("tenant".into(), "acme".into())]),
            block_event("injection/sqli", "critical")
        )));
        // Wrong tenant.
        assert!(!f.matches(&env_with(
            BTreeMap::from([("tenant".into(), "contoso".into())]),
            block_event("injection/sqli", "critical")
        )));
        // Wrong severity.
        assert!(!f.matches(&env_with(
            BTreeMap::from([("tenant".into(), "acme".into())]),
            block_event("injection/sqli", "high")
        )));
        // Wrong rule.
        assert!(!f.matches(&env_with(
            BTreeMap::from([("tenant".into(), "acme".into())]),
            block_event("structural/header", "critical")
        )));
    }

    // ----- Glob tests -----

    #[test]
    fn glob_anchored_prefix() {
        let g = Glob::new("injection/*");
        assert!(g.matches("injection/sqli"));
        assert!(g.matches("injection/xss"));
        assert!(!g.matches("structural/header"));
        assert!(!g.matches("noinjection/x"));
    }

    #[test]
    fn glob_anchored_suffix() {
        let g = Glob::new("*/sqli");
        assert!(g.matches("injection/sqli"));
        assert!(g.matches("signatures/sqli"));
        assert!(!g.matches("injection/xss"));
    }

    #[test]
    fn glob_anchored_middle() {
        let g = Glob::new("*sqli*");
        assert!(g.matches("injection/sqli"));
        assert!(g.matches("xsqlix"));
        assert!(!g.matches("xss"));
    }

    #[test]
    fn glob_exact() {
        let g = Glob::new("injection/sqli");
        assert!(g.matches("injection/sqli"));
        assert!(!g.matches("injection/sqlix"));
        assert!(!g.matches("xinjection/sqli"));
    }

    #[test]
    fn glob_all_wildcards() {
        let g = Glob::new("*");
        assert!(g.matches(""));
        assert!(g.matches("anything"));
    }
}
