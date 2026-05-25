use crate::clock::{Clock, SystemClock};
use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request::Request;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

/// Bounded LRU token bucket keyed by source IP.
///
/// **Why not `governor`:** governor's `RateLimiter::keyed` is backed by a
/// `DashMap` with no upper bound on the key set. An attacker rotating
/// source IPs (trivially achievable behind a misconfigured trusted edge,
/// see [`crate::request::client_ip`]) inflates the map by one entry per
/// unique IP, no eviction, no GC. WASM linear memory caps eventually trap
/// the request and Traefik's plugin-failure directive kicks in — a cheap
/// memory-DoS against the plugin instance.
///
/// This implementation hard-caps the tracked-IP count at `max_tracked_ips`
/// (default 50,000 — see [`crate::config::ReputationConfig`]) and evicts
/// the least-recently-seen entry when the cap is reached. The hot path is
/// a single HashMap lookup + a small amount of bucket math; no async, no
/// futures, no DashMap, no dependency outside std.
struct LruTokenBuckets<C: Clock> {
    /// Tracks (tokens, last_refill_nanos, last_touch_seq). The seq lets us
    /// evict the LRU entry in O(n) on overflow — acceptable since overflow
    /// is by definition rare (~once per `max_tracked_ips` requests).
    buckets: HashMap<IpAddr, Bucket>,
    cap: usize,
    quota_per_sec: u32,
    next_seq: u64,
    clock: C,
}

#[derive(Clone, Copy)]
struct Bucket {
    /// Token count as a float so partial refills accumulate correctly.
    tokens: f64,
    /// Clock reading at the last refill, used to compute elapsed for the
    /// next refill.
    last_refill: Duration,
    /// Monotonic counter incremented on every access; lowest seq → oldest.
    last_seen_seq: u64,
}

impl<C: Clock> LruTokenBuckets<C> {
    fn new(quota_per_sec: u32, cap: usize, clock: C) -> LruTokenBuckets<C> {
        LruTokenBuckets {
            buckets: HashMap::new(),
            // A cap of 0 would deadlock the eviction loop; treat it as 1.
            cap: cap.max(1),
            // A quota of 0 would mean "never allow anything"; the test
            // suite and existing call sites expect "at least 1 rps".
            quota_per_sec: quota_per_sec.max(1),
            next_seq: 0,
            clock,
        }
    }

    /// Returns `true` iff the request is **allowed** (i.e. a token was
    /// consumed). Returns `false` when the per-IP budget is exhausted.
    fn check(&mut self, ip: IpAddr) -> bool {
        let now = self.clock.now();
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let quota = self.quota_per_sec as f64;

        // Evict LRU only when we're about to insert AND we're at the cap.
        if !self.buckets.contains_key(&ip) && self.buckets.len() >= self.cap {
            if let Some(oldest) = self
                .buckets
                .iter()
                .min_by_key(|(_, b)| b.last_seen_seq)
                .map(|(k, _)| *k)
            {
                self.buckets.remove(&oldest);
            }
        }

        let bucket = self.buckets.entry(ip).or_insert(Bucket {
            tokens: quota,
            last_refill: now,
            last_seen_seq: seq,
        });
        // Refill: add `quota * elapsed_sec` tokens, capped at `quota`.
        let elapsed = now.saturating_sub(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * quota).min(quota);
        bucket.last_refill = now;
        bucket.last_seen_seq = seq;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-instance rate limiting plus static IP allow/deny lists.
///
/// State lives in `Mutex<LruTokenBuckets>` so concurrent access (e.g. from
/// host runtimes that share an `Engine` across worker threads in unit
/// tests) is safe. The WASM guest is single-threaded so the lock is
/// uncontended in production.
pub struct ReputationDetector {
    state: Mutex<LruTokenBuckets<SystemClock>>,
    deny_list: Vec<IpAddr>,
}

impl ReputationDetector {
    /// `per_second` requests allowed per source IP before flagging.
    /// A value of 0 is treated as 1 (the limiter requires a non-zero quota).
    /// The internal map is hard-capped at the default 50,000 keys; use
    /// [`ReputationDetector::with_capacity`] to set a different cap.
    pub fn new(per_second: u32, deny_list: Vec<IpAddr>) -> ReputationDetector {
        ReputationDetector::with_capacity(per_second, deny_list, 50_000)
    }

    /// Like [`ReputationDetector::new`] but with an explicit cap on the
    /// number of distinct source IPs tracked at once. When the cap is
    /// reached, the least-recently-seen entry is evicted to make room.
    pub fn with_capacity(
        per_second: u32,
        deny_list: Vec<IpAddr>,
        max_tracked_ips: usize,
    ) -> ReputationDetector {
        ReputationDetector {
            state: Mutex::new(LruTokenBuckets::new(
                per_second,
                max_tracked_ips,
                SystemClock::new(),
            )),
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
        let allowed = self
            .state
            .lock()
            .map(|mut s| s.check(req.source_ip))
            .unwrap_or(true); // poisoned mutex: fail-open, audit elsewhere
        if !allowed {
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

// `RefCell` is intentionally not used at module scope; the field above is
// `Mutex` for Sync. The detector list passed to `Engine` is `Box<dyn
// Detector + Send + Sync>` and `Mutex<T>` is `Sync` when `T: Send`.
// (The `RefCell` import below is for tests only.)
#[allow(dead_code)]
fn _silence_refcell_import_for_tests(_x: RefCell<()>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_from(ip: &str) -> Request {
        Request::build(
            "GET",
            "h",
            "/",
            "",
            vec![],
            vec![],
            false,
            ip.parse().unwrap(),
        )
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
            if det
                .inspect(&req_from("5.5.5.5"))
                .iter()
                .any(|x| x.rule == "rate_limited")
            {
                limited = true;
            }
        }
        assert!(limited, "burst should trip the rate limiter");
    }

    /// Regression guard for NEW-H2: the tracked-IP map must be bounded.
    /// Sending 10x the cap unique IPs should leave the internal map at
    /// most `cap` entries — the LRU eviction keeps memory growth O(cap).
    #[test]
    fn bounded_map_evicts_lru_when_full() {
        let cap = 16;
        let det = ReputationDetector::with_capacity(100, vec![], cap);
        // Send 10x cap unique IPs.
        for i in 0..(cap * 10) {
            let octet = (i & 0xff) as u8;
            let high = ((i >> 8) & 0xff) as u8;
            let ip_str = format!("10.0.{high}.{octet}");
            let _ = det.inspect(&req_from(&ip_str));
        }
        let guard = det.state.lock().unwrap();
        assert!(
            guard.buckets.len() <= cap,
            "map should be bounded at {} entries, was {}",
            cap,
            guard.buckets.len()
        );
    }

    /// Eviction policy is least-recently-seen: an IP that keeps making
    /// requests must not be evicted in favor of new IPs.
    #[test]
    fn evicts_least_recently_used_not_most_recently_used() {
        let cap = 4;
        let det = ReputationDetector::with_capacity(100, vec![], cap);
        // Fill the cap with 4 IPs.
        for i in 0..cap {
            let _ = det.inspect(&req_from(&format!("10.0.0.{i}")));
        }
        // Re-touch the first IP so it becomes MRU, not LRU.
        let _ = det.inspect(&req_from("10.0.0.0"));
        // Send one more new IP; should evict 10.0.0.1 (now LRU), not 10.0.0.0.
        let _ = det.inspect(&req_from("10.0.0.99"));
        let guard = det.state.lock().unwrap();
        assert!(
            guard
                .buckets
                .contains_key(&"10.0.0.0".parse::<IpAddr>().unwrap()),
            "re-touched IP must survive eviction"
        );
        assert!(
            !guard
                .buckets
                .contains_key(&"10.0.0.1".parse::<IpAddr>().unwrap()),
            "LRU entry should have been evicted"
        );
    }
}
