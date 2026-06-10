//! Per-subscriber dead-letter queue (in-memory ring buffer).
//!
//! The current implementation keeps it simple: a `Mutex<VecDeque<Envelope>>` per subscriber
//! with a fixed capacity. On overflow we drop the OLDEST entry —
//! preserving recent failures over ancient ones is more useful for
//! debugging. A separate `overflow_count` counter records how many
//! drops happened so operators can alert on it.
//!
//! A SQLite-backed durable DLQ is future work; the in-memory variant
//! stays as the default for low-volume deployments.

use std::collections::VecDeque;
use std::sync::Mutex;

use crate::envelope::Envelope;

#[derive(Debug)]
pub struct Dlq {
    inner: Mutex<DlqInner>,
    capacity: usize,
}

#[derive(Debug)]
struct DlqInner {
    queue: VecDeque<Envelope>,
    overflow_count: u64,
}

impl Dlq {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(DlqInner {
                queue: VecDeque::with_capacity(capacity),
                overflow_count: 0,
            }),
            capacity,
        }
    }

    /// Push to the tail, dropping the head if at capacity.
    pub fn push(&self, env: Envelope) {
        let mut g = self.inner.lock().unwrap();
        if g.queue.len() >= self.capacity {
            g.queue.pop_front();
            g.overflow_count = g.overflow_count.saturating_add(1);
        }
        g.queue.push_back(env);
    }

    /// Current depth.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Total number of evicted-on-overflow envelopes since startup.
    pub fn overflow_count(&self) -> u64 {
        self.inner.lock().unwrap().overflow_count
    }

    /// Drain all entries (used by replay). Caller takes ownership.
    pub fn drain_all(&self) -> Vec<Envelope> {
        let mut g = self.inner.lock().unwrap();
        g.queue.drain(..).collect()
    }

    /// Read-only snapshot of the current contents. Useful for the
    /// future admin endpoint without disturbing the queue.
    pub fn snapshot(&self) -> Vec<Envelope> {
        self.inner.lock().unwrap().queue.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeSource;
    use std::collections::BTreeMap;

    fn env(tag: &str) -> Envelope {
        Envelope::new(
            serde_json::json!({"tag": tag}),
            EnvelopeSource {
                middleware: None,
                router: None,
                entry_point: None,
                relay_instance: "r".into(),
            },
            BTreeMap::new(),
        )
    }

    #[test]
    fn push_within_capacity_keeps_all() {
        let dlq = Dlq::new(3);
        for i in 0..3 {
            dlq.push(env(&format!("{i}")));
        }
        assert_eq!(dlq.len(), 3);
        assert_eq!(dlq.overflow_count(), 0);
    }

    #[test]
    fn push_at_capacity_drops_oldest() {
        let dlq = Dlq::new(2);
        dlq.push(env("0"));
        dlq.push(env("1"));
        dlq.push(env("2")); // evicts "0"
        let snap = dlq.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].event["tag"], "1");
        assert_eq!(snap[1].event["tag"], "2");
        assert_eq!(dlq.overflow_count(), 1);
    }

    #[test]
    fn drain_all_clears_queue() {
        let dlq = Dlq::new(3);
        dlq.push(env("a"));
        dlq.push(env("b"));
        let drained = dlq.drain_all();
        assert_eq!(drained.len(), 2);
        assert!(dlq.is_empty());
    }
}
