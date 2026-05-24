use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request::Request;
use governor::clock::DefaultClock;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use std::net::IpAddr;
use std::num::NonZeroU32;

type IpLimiter = RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>;

/// Per-instance rate limiting plus static IP allow/deny lists.
pub struct ReputationDetector {
    limiter: IpLimiter,
    deny_list: Vec<IpAddr>,
}

impl ReputationDetector {
    /// `per_second` requests allowed per source IP before flagging.
    /// A value of 0 is treated as 1 (the limiter requires a non-zero quota).
    pub fn new(per_second: u32, deny_list: Vec<IpAddr>) -> ReputationDetector {
        let quota = Quota::per_second(NonZeroU32::new(per_second.max(1)).unwrap());
        ReputationDetector {
            limiter: RateLimiter::keyed(quota),
            deny_list,
        }
    }
}

impl Detector for ReputationDetector {
    fn group(&self) -> Group {
        Group::Reputation
    }

    fn inspect(&self, req: &Request) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        if self.deny_list.contains(&req.source_ip) {
            verdicts.push(Verdict {
                group: Group::Reputation,
                rule: "ip_denied",
                severity: Severity::High,
                detail: format!("source IP {} on deny list", req.source_ip),
            });
        }
        if self.limiter.check_key(&req.source_ip).is_err() {
            verdicts.push(Verdict {
                group: Group::Reputation,
                rule: "rate_limited",
                severity: Severity::Medium,
                detail: format!("source IP {} exceeded rate quota", req.source_ip),
            });
        }
        verdicts
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_from(ip: &str) -> Request {
        Request::build("GET", "h", "/", "", vec![], vec![], false, ip.parse().unwrap())
    }

    #[test]
    fn flags_denied_ip() {
        let det = ReputationDetector::new(1000, vec!["9.9.9.9".parse().unwrap()]);
        let v = det.inspect(&req_from("9.9.9.9"));
        assert!(v.iter().any(|x| x.rule == "ip_denied"));
    }

    #[test]
    fn rate_limits_burst_from_one_ip() {
        let det = ReputationDetector::new(1, vec![]);
        let mut limited = false;
        for _ in 0..50 {
            if det.inspect(&req_from("5.5.5.5")).iter().any(|x| x.rule == "rate_limited") {
                limited = true;
            }
        }
        assert!(limited, "burst should trip the rate limiter");
    }
}
