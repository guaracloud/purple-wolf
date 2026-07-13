//! Retry schedule: exponential backoff with ±20% jitter, capped.
//!
//! Used by the HTTP subscriber sink to space out retry attempts.

use rand::Rng;
use std::time::Duration;

use crate::config::RetryConfig;

#[derive(Debug, Clone)]
pub struct RetrySchedule {
    base_delay_ms: u64,
    max_delay_ms: u64,
}

impl RetrySchedule {
    pub fn from_config(c: &RetryConfig) -> Self {
        Self {
            base_delay_ms: c.base_delay_ms,
            max_delay_ms: c.max_delay_ms,
        }
    }

    /// Delay to sleep before retry `attempt` (1-based — call after a
    /// failed attempt N to get the delay before attempt N+1). Returns
    /// 0 if either side of the config is zero (caller should detect
    /// that as "retries disabled").
    pub fn next_delay(&self, attempt: u32) -> Duration {
        if self.base_delay_ms == 0 || self.max_delay_ms == 0 {
            return Duration::from_millis(0);
        }
        // Cap the shift so 2^attempt doesn't overflow u64 for absurd
        // attempt counts. 20 shifts is `base * 1M` — well over any
        // reasonable max_delay_ms cap so we'll be clamped anyway.
        let shift = attempt.min(20);
        let exp = self.base_delay_ms.saturating_mul(1u64 << shift);
        let capped = exp.min(self.max_delay_ms);
        let jitter = rand::rng().random_range(0.8..=1.2);
        let jittered = (capped as f64 * jitter) as u64;
        Duration::from_millis(jittered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(base: u64, max: u64) -> RetrySchedule {
        RetrySchedule::from_config(&RetryConfig {
            max_attempts: 8,
            base_delay_ms: base,
            max_delay_ms: max,
        })
    }

    #[test]
    fn delay_grows_then_caps() {
        let s = schedule(100, 10_000);
        // For each attempt, the un-jittered exponential is base * 2^n.
        // The jittered result is in [0.8 .. 1.2] * un-jittered, clamped
        // by max_delay_ms.
        let d0 = s.next_delay(0);
        let d3 = s.next_delay(3);
        let d10 = s.next_delay(10);

        // d0: 100ms base — jittered to [80, 120]ms.
        assert!(d0 >= Duration::from_millis(80) && d0 <= Duration::from_millis(120));
        // d3: 100 * 8 = 800ms — jittered to [640, 960]ms.
        assert!(d3 >= Duration::from_millis(640) && d3 <= Duration::from_millis(960));
        // d10: exponentially huge → capped at max_delay_ms then jittered.
        // max_delay_ms=10000 → jittered to [8000, 12000]ms.
        assert!(d10 >= Duration::from_millis(8000) && d10 <= Duration::from_millis(12000));
    }

    #[test]
    fn next_delay_is_zero_when_base_or_max_zero() {
        assert_eq!(schedule(0, 1000).next_delay(1), Duration::from_millis(0));
        assert_eq!(schedule(1000, 0).next_delay(1), Duration::from_millis(0));
    }

    #[test]
    fn next_delay_does_not_overflow_at_absurd_attempts() {
        let s = schedule(1, u64::MAX);
        // Must not panic at high attempts (saturating_mul + clamped
        // shift do the work).
        let _ = s.next_delay(100);
        let _ = s.next_delay(u32::MAX);
    }
}
