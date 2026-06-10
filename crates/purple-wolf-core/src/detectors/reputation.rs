use crate::clock::{Clock, SystemClock};
use crate::detectors::{Detector, Group, Severity, Verdict};
use crate::request::Request;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Duration;

/// Sentinel link value meaning "no node" (list head/tail terminator).
/// `usize::MAX` is safe because the slab can never grow that large —
/// `cap` is bounded by `max_tracked_ips`.
const NIL: usize = usize::MAX;

/// Bounded LRU token bucket keyed by source IP, with **O(1)** eviction.
///
/// **Why not `governor`:** governor's `RateLimiter::keyed` is backed by a
/// `DashMap` with no upper bound on the key set. An attacker rotating
/// source IPs (trivially achievable behind a misconfigured trusted edge,
/// see [`crate::request::client_ip`]) inflates the map by one entry per
/// unique IP, no eviction, no GC. WASM linear memory caps eventually trap
/// the request and Traefik's plugin-failure directive kicks in — a cheap
/// memory-DoS against the plugin instance.
///
/// **Why not the previous in-crate version:** v0.3 hard-capped the map but
/// evicted via an O(n) `min_by_key` scan over every tracked IP. That made
/// the *benign* case cheap (overflow is rare) but the *adversarial* case
/// quadratic: once an attacker fills the map to `cap` by rotating IPs,
/// every subsequent new-IP request scans all `cap` entries — turning the
/// memory-DoS mitigation into a CPU-DoS lever that eats the plugin's CPU
/// budget far below the benign RPS ceiling.
///
/// This implementation keeps the hard cap but makes **every** operation —
/// lookup, refill, touch, insert, and eviction — O(1). State lives in a
/// fixed-capacity slab (`Vec<Node>`); an intrusive doubly-linked list
/// threads the slab in recency order (`head` = most-recently-seen, `tail`
/// = least). A `HashMap<IpAddr, usize>` indexes IP → slab slot. The slab
/// grows to `cap` and never shrinks; once full, an insert evicts `tail`
/// and reuses *that exact slot* in place (no separate free list — slots
/// are only ever freed by an insert that immediately reclaims them). No
/// async, no futures, no DashMap, no dependency outside std.
struct LruTokenBuckets<C: Clock> {
    /// IP → slab index. Bounded at `cap` entries.
    index: HashMap<IpAddr, usize>,
    /// Backing slab. Grows to at most `cap` nodes, then is reused in place.
    slab: Vec<Node>,
    /// Most-recently-seen slot, or `NIL` when empty.
    head: usize,
    /// Least-recently-seen slot (eviction victim), or `NIL` when empty.
    tail: usize,
    cap: usize,
    quota_per_sec: u32,
    clock: C,
}

/// One slab slot: a token bucket plus intrusive prev/next links into the
/// recency list. `ip` is `None` only transiently inside [`evict_tail`].
struct Node {
    ip: Option<IpAddr>,
    /// Token count as a float so partial refills accumulate correctly.
    tokens: f64,
    /// Clock reading at the last refill, used to compute elapsed for the
    /// next refill.
    last_refill: Duration,
    prev: usize,
    next: usize,
}

impl<C: Clock> LruTokenBuckets<C> {
    fn new(quota_per_sec: u32, cap: usize, clock: C) -> LruTokenBuckets<C> {
        // A cap of 0 would leave nothing to track; treat it as 1.
        let cap = cap.max(1);
        LruTokenBuckets {
            index: HashMap::with_capacity(cap),
            slab: Vec::with_capacity(cap),
            head: NIL,
            tail: NIL,
            cap,
            // A quota of 0 would mean "never allow anything"; the test
            // suite and existing call sites expect "at least 1 rps".
            quota_per_sec: quota_per_sec.max(1),
            clock,
        }
    }

    /// Number of distinct IPs currently tracked. Never exceeds `cap`.
    /// Test-only introspection into the bounded map's size invariant.
    #[cfg(test)]
    fn tracked_len(&self) -> usize {
        self.index.len()
    }

    /// Whether `ip` currently has a live bucket. Test-only introspection
    /// into eviction ordering.
    #[cfg(test)]
    fn tracked_contains(&self, ip: &IpAddr) -> bool {
        self.index.contains_key(ip)
    }

    /// Unlink `slot` from the recency list (it must currently be linked).
    fn unlink(&mut self, slot: usize) {
        let (prev, next) = {
            let n = &self.slab[slot];
            (n.prev, n.next)
        };
        if prev != NIL {
            self.slab[prev].next = next;
        } else {
            self.head = next;
        }
        if next != NIL {
            self.slab[next].prev = prev;
        } else {
            self.tail = prev;
        }
    }

    /// Push `slot` to the front of the recency list (becomes MRU).
    fn push_front(&mut self, slot: usize) {
        let old_head = self.head;
        {
            let n = &mut self.slab[slot];
            n.prev = NIL;
            n.next = old_head;
        }
        if old_head != NIL {
            self.slab[old_head].prev = slot;
        }
        self.head = slot;
        if self.tail == NIL {
            self.tail = slot;
        }
    }

    /// Move an already-linked slot to the front (mark most-recently-seen).
    fn touch(&mut self, slot: usize) {
        if self.head == slot {
            return;
        }
        self.unlink(slot);
        self.push_front(slot);
    }

    /// Evict the LRU node (`tail`): unlink it from the recency list and
    /// drop its IP from the index. Returns the now-detached slot index for
    /// immediate in-place reuse by the caller. The returned slot has `prev`
    /// and `next` left dangling — the caller MUST re-initialize and
    /// re-link it (via `push_front`) before any other list operation.
    fn evict_tail(&mut self) -> usize {
        let victim = self.tail;
        debug_assert!(victim != NIL, "evict_tail called on empty list");
        self.unlink(victim);
        if let Some(ip) = self.slab[victim].ip.take() {
            self.index.remove(&ip);
        }
        victim
    }

    /// Acquire a slot for a new IP: grow the slab while under `cap`,
    /// otherwise evict the LRU and reuse its slot. The returned slot is
    /// detached from the recency list; the caller links it via `push_front`.
    fn acquire_slot(&mut self) -> usize {
        if self.slab.len() < self.cap {
            // Grow: the slab has not yet reached `cap`.
            self.slab.push(Node {
                ip: None,
                tokens: 0.0,
                last_refill: Duration::ZERO,
                prev: NIL,
                next: NIL,
            });
            return self.slab.len() - 1;
        }
        // At capacity: evict the least-recently-seen entry and reuse it.
        self.evict_tail()
    }

    /// Returns `true` iff the request is **allowed** (i.e. a token was
    /// consumed). Returns `false` when the per-IP budget is exhausted.
    /// Every path is O(1).
    fn check(&mut self, ip: IpAddr) -> bool {
        let now = self.clock.now();
        let quota = self.quota_per_sec as f64;

        if let Some(&slot) = self.index.get(&ip) {
            // Known IP: refill, touch, consume.
            self.touch(slot);
            let n = &mut self.slab[slot];
            let elapsed = now.saturating_sub(n.last_refill).as_secs_f64();
            n.tokens = (n.tokens + elapsed * quota).min(quota);
            n.last_refill = now;
            return consume(&mut n.tokens);
        }

        // New IP: acquire a slot (may evict the LRU), initialize a fresh
        // full bucket so a reused slot never carries stale token state.
        let slot = self.acquire_slot();
        {
            let n = &mut self.slab[slot];
            n.ip = Some(ip);
            n.tokens = quota;
            n.last_refill = now;
        }
        self.index.insert(ip, slot);
        self.push_front(slot);
        consume(&mut self.slab[slot].tokens)
    }
}

/// Consume one token if available. Returns whether the request is allowed.
fn consume(tokens: &mut f64) -> bool {
    if *tokens >= 1.0 {
        *tokens -= 1.0;
        true
    } else {
        false
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
            guard.tracked_len() <= cap,
            "map should be bounded at {} entries, was {}",
            cap,
            guard.tracked_len()
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
            guard.tracked_contains(&"10.0.0.0".parse::<IpAddr>().unwrap()),
            "re-touched IP must survive eviction"
        );
        assert!(
            !guard.tracked_contains(&"10.0.0.1".parse::<IpAddr>().unwrap()),
            "LRU entry should have been evicted"
        );
    }

    /// The eviction order must be strict LRU even under heavy churn: after
    /// filling the cap and then inserting many fresh IPs, exactly the most
    /// recently seen `cap` IPs survive and the map never exceeds `cap`.
    /// This is the adversarial case (IP-rotation flood) the O(1) limiter
    /// must handle in constant work per request.
    #[test]
    fn eviction_order_is_strict_lru_under_churn() {
        let cap = 8;
        let det = ReputationDetector::with_capacity(1000, vec![], cap);
        let total = cap * 5;
        for i in 0..total {
            let _ = det.inspect(&req_from(&format!("10.0.{}.{}", i / 256, i % 256)));
            // Invariant must hold at every step, not just at the end.
            assert!(det.state.lock().unwrap().tracked_len() <= cap);
        }
        let guard = det.state.lock().unwrap();
        assert_eq!(guard.tracked_len(), cap, "map should be exactly full");
        // The last `cap` IPs inserted must all still be present...
        for i in (total - cap)..total {
            let ip = format!("10.0.{}.{}", i / 256, i % 256)
                .parse::<IpAddr>()
                .unwrap();
            assert!(
                guard.tracked_contains(&ip),
                "most-recent IP {ip} must survive churn"
            );
        }
        // ...and the first one inserted must be long gone.
        let oldest = "10.0.0.0".parse::<IpAddr>().unwrap();
        assert!(
            !guard.tracked_contains(&oldest),
            "oldest IP must have been evicted under churn"
        );
    }

    /// When an IP is evicted and later re-seen, it must start with a fresh,
    /// full token bucket — no stale token/refill state may survive in a
    /// reused internal slot. Regression guard for slot-reuse correctness in
    /// the O(1) slab-backed LRU.
    #[test]
    fn refill_math_survives_slot_reuse() {
        let cap = 2;
        // quota 1/s: a single IP gets one token, the second hit is limited.
        let det = ReputationDetector::with_capacity(1, vec![], cap);
        let victim = "10.0.0.1";
        // Exhaust the victim's bucket.
        let _ = det.inspect(&req_from(victim)); // allowed (consumes the token)
        assert!(
            det.inspect(&req_from(victim))
                .iter()
                .any(|x| x.rule == "rate_limited"),
            "second hit from the same IP should be limited"
        );
        // Evict the victim by flooding `cap` other fresh IPs.
        for i in 0..cap {
            let _ = det.inspect(&req_from(&format!("10.9.9.{i}")));
        }
        assert!(
            !det.state
                .lock()
                .unwrap()
                .tracked_contains(&victim.parse::<IpAddr>().unwrap()),
            "victim should have been evicted"
        );
        // Re-seeing the victim must hand it a fresh full bucket → allowed,
        // not carrying the exhausted state from its reused slot.
        assert!(
            det.inspect(&req_from(victim))
                .iter()
                .all(|x| x.rule != "rate_limited"),
            "re-seen IP must get a fresh bucket after slot reuse"
        );
    }
}
