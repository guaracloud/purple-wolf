//! Time abstraction so the reputation rate-limiter is portable across
//! native and WASM (where `Instant::now()` semantics differ).
use std::time::Duration;

/// Returns monotonically non-decreasing nanoseconds since an arbitrary epoch.
/// Implementations need only guarantee monotonicity within a single instance.
pub trait Clock: Send + Sync + 'static {
    /// Time elapsed since the clock's epoch.
    fn now(&self) -> Duration;
}

/// Native clock backed by `std::time::Instant`.
pub struct SystemClock {
    epoch: std::time::Instant,
}

impl SystemClock {
    /// Construct a SystemClock whose epoch is `now`.
    pub fn new() -> SystemClock {
        SystemClock {
            epoch: std::time::Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn system_clock_is_monotonic() {
        let c = SystemClock::new();
        let a = c.now();
        std::thread::sleep(Duration::from_millis(2));
        let b = c.now();
        assert!(b >= a);
    }
}
