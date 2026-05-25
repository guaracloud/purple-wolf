//! Detector trait, grouping types, and built-in detector implementations.

/// SQLi/XSS detector backed by libinjection.
pub mod injection;
/// Per-IP rate limiter and static deny-list detector.
pub mod reputation;
/// Literal-pattern signature detector using Aho-Corasick multi-pattern search.
pub mod signatures;
/// Structural anomaly detector for HTTP method and header limits.
pub mod structural;

use crate::request::Request;

/// Logical grouping for a set of related detectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// SQL injection and XSS detection.
    Injection,
    /// Literal bad-pattern signatures (path traversal, RCE, scanner UAs).
    Signatures,
    /// Structural anomaly checks (method allowlist, header size/count).
    Structural,
    /// Per-IP rate limiting and static deny list.
    Reputation,
}

impl Group {
    /// Lowercase string tag for this group, used in audit logs and config keys.
    pub fn as_str(&self) -> &'static str {
        match self {
            Group::Injection => "injection",
            Group::Signatures => "signatures",
            Group::Structural => "structural",
            Group::Reputation => "reputation",
        }
    }
}

/// Verdict severity for downstream filtering in audit logs.
///
/// The variant order is meaningful: `Low < Medium < High < Critical`. The
/// derived `PartialOrd`/`Ord` lets `policy::decide` pick the highest-severity
/// blocking verdict so the audit-log `blocked_rule` always names the worst
/// thing the request did, not the first thing a detector happened to find.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    // No detector currently emits Low, but it's part of the severity ladder —
    // future signatures (e.g. minor scanner UA hits) will need it. Kept on
    // purpose so the public Severity API stays complete.
    #[allow(dead_code)]
    /// Informational signal; lowest priority.
    Low,
    /// Notable anomaly that warrants review.
    Medium,
    /// Strong signal of malicious intent.
    High,
    /// Definitive attack pattern; highest priority.
    Critical,
}

impl Severity {
    /// Lowercase tag suitable for audit-log serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// One detection hit.
#[derive(Debug, Clone)]
pub struct Verdict {
    /// Detector group that produced this verdict.
    pub group: Group,
    /// Short identifier for the matched rule (e.g. `"sqli"`, `"path_traversal"`).
    pub rule: &'static str,
    /// Severity of this detection.
    pub severity: Severity,
    /// Human-readable description of what was detected and where.
    pub detail: String,
}

/// A detector inspects a request and returns zero or more verdicts.
pub trait Detector: Send + Sync {
    /// The group this detector belongs to.
    fn group(&self) -> Group;
    /// Inspect `req` and return any verdicts found.
    fn inspect(&self, req: &Request) -> Vec<Verdict>;
}

/// Holds every detector and runs the enabled ones.
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    /// Create an engine from the supplied list of detectors.
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Engine {
        Engine { detectors }
    }

    /// Run detectors whose group is in `enabled`. Returns all verdicts.
    pub fn inspect(&self, req: &Request, enabled: &[Group]) -> Vec<Verdict> {
        self.detectors
            .iter()
            .filter(|d| enabled.contains(&d.group()))
            .flat_map(|d| d.inspect(req))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Request;
    use std::net::IpAddr;

    struct AlwaysHit(Group);
    impl Detector for AlwaysHit {
        fn group(&self) -> Group {
            self.0
        }
        fn inspect(&self, _req: &Request) -> Vec<Verdict> {
            vec![Verdict {
                group: self.0,
                rule: "test",
                severity: Severity::High,
                detail: "hit".into(),
            }]
        }
    }

    fn req() -> Request {
        Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![],
            vec![],
            false,
            "1.2.3.4".parse::<IpAddr>().unwrap(),
        )
    }

    #[test]
    fn engine_runs_only_enabled_groups() {
        let engine = Engine::new(vec![
            Box::new(AlwaysHit(Group::Injection)),
            Box::new(AlwaysHit(Group::Structural)),
        ]);
        let verdicts = engine.inspect(&req(), &[Group::Injection]);
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].group, Group::Injection);
    }
}
