pub mod injection;
pub mod signatures;
pub mod structural;
pub mod reputation;

use crate::request_model::RequestView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Injection,
    Signatures,
    Structural,
    Reputation,
}

impl Group {
    pub fn as_str(&self) -> &'static str {
        match self {
            Group::Injection => "injection",
            Group::Signatures => "signatures",
            Group::Structural => "structural",
            Group::Reputation => "reputation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// One detection hit.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub group: Group,
    pub rule: &'static str,
    pub severity: Severity,
    pub detail: String,
}

/// A detector inspects a request and returns zero or more verdicts.
pub trait Detector: Send + Sync {
    fn group(&self) -> Group;
    fn inspect(&self, req: &RequestView) -> Vec<Verdict>;
}

/// Holds every detector and runs the enabled ones.
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Engine {
        Engine { detectors }
    }

    /// Run detectors whose group is in `enabled`. Returns all verdicts.
    pub fn inspect(&self, req: &RequestView, enabled: &[Group]) -> Vec<Verdict> {
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
    use crate::request_model::RequestView;
    use std::net::IpAddr;

    struct AlwaysHit(Group);
    impl Detector for AlwaysHit {
        fn group(&self) -> Group { self.0 }
        fn inspect(&self, _req: &RequestView) -> Vec<Verdict> {
            vec![Verdict {
                group: self.0,
                rule: "test",
                severity: Severity::High,
                detail: "hit".into(),
            }]
        }
    }

    fn req() -> RequestView {
        RequestView::build("GET", "h", "/", "", vec![], vec![], false,
            "1.2.3.4".parse::<IpAddr>().unwrap())
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
