//! Prometheus metrics surface.
//!
//! Cardinality discipline: every label here is bounded by the
//! operator's config (subscriber_id, enricher name, source_id from
//! config), not by envelope content. Envelope label *values* are
//! never used as metric labels — that's how a careless tenant
//! taxonomy ends up exploding Prometheus storage.

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    TextEncoder,
};

/// All metric handles. Hold this behind an `Arc` and share with every
/// pipeline task that needs to record.
pub struct Metrics {
    pub registry: Registry,
    pub build_info: IntGaugeVec,
    pub ready: IntGauge,
    /// Raw lines read from each source.
    pub source_lines: IntCounterVec,
    /// Parser outcomes: `ok` / `not_pw` / `error`.
    pub parsed_events: IntCounterVec,
    /// Enricher calls: `ok` / `error` / `timeout` per enricher name.
    pub enricher_calls: IntCounterVec,
    /// Per-subscriber: events matching the filter.
    pub subscribers_matched: IntCounterVec,
    /// Per-subscriber delivery outcomes.
    pub deliveries: IntCounterVec,
    /// Per-subscriber delivery latency in seconds.
    pub delivery_latency_seconds: HistogramVec,
    /// Per-subscriber DLQ depth gauge.
    pub dlq_depth: IntGaugeVec,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();

        let build_info = IntGaugeVec::new(
            Opts::new(
                "pwrelay_build_info",
                "purple-wolf-relay build metadata (always 1)",
            ),
            &["version", "git_sha"],
        )?;
        let git_sha = option_env!("PURPLE_WOLF_RELAY_GIT_SHA").unwrap_or("unknown");
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION"), git_sha])
            .set(1);
        registry.register(Box::new(build_info.clone()))?;

        let ready = IntGauge::new(
            "pwrelay_ready",
            "1 if the relay pipeline considers itself ready (see /readyz)",
        )?;
        registry.register(Box::new(ready.clone()))?;

        let source_lines = IntCounterVec::new(
            Opts::new(
                "pwrelay_source_lines_total",
                "Lines read from each configured source.",
            ),
            &["source_id"],
        )?;
        registry.register(Box::new(source_lines.clone()))?;

        let parsed_events = IntCounterVec::new(
            Opts::new(
                "pwrelay_parsed_events_total",
                "Parser outcomes by result class.",
            ),
            &["result"],
        )?;
        registry.register(Box::new(parsed_events.clone()))?;

        let enricher_calls = IntCounterVec::new(
            Opts::new(
                "pwrelay_enricher_calls_total",
                "Enricher invocations by name and outcome.",
            ),
            &["enricher", "result"],
        )?;
        registry.register(Box::new(enricher_calls.clone()))?;

        let subscribers_matched = IntCounterVec::new(
            Opts::new(
                "pwrelay_subscribers_matched_total",
                "Envelopes that matched each subscriber's filter.",
            ),
            &["subscriber_id"],
        )?;
        registry.register(Box::new(subscribers_matched.clone()))?;

        let deliveries = IntCounterVec::new(
            Opts::new(
                "pwrelay_deliveries_total",
                "Delivery outcomes per subscriber.",
            ),
            &["subscriber_id", "outcome"],
        )?;
        registry.register(Box::new(deliveries.clone()))?;

        let delivery_latency_seconds = HistogramVec::new(
            HistogramOpts::new(
                "pwrelay_delivery_latency_seconds",
                "End-to-end delivery latency (per attempt) seen by each subscriber.",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]),
            &["subscriber_id"],
        )?;
        registry.register(Box::new(delivery_latency_seconds.clone()))?;

        let dlq_depth = IntGaugeVec::new(
            Opts::new("pwrelay_dlq_depth", "Current DLQ depth per subscriber."),
            &["subscriber_id"],
        )?;
        registry.register(Box::new(dlq_depth.clone()))?;

        Ok(Self {
            registry,
            build_info,
            ready,
            source_lines,
            parsed_events,
            enricher_calls,
            subscribers_matched,
            deliveries,
            delivery_latency_seconds,
            dlq_depth,
        })
    }

    /// Render the Prometheus text exposition format.
    pub fn render(&self) -> Vec<u8> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buf = Vec::with_capacity(4096);
        encoder
            .encode(&metric_families, &mut buf)
            .expect("encoding to a Vec<u8> cannot fail");
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_renders_full_family_set() {
        let m = Metrics::new().unwrap();
        m.source_lines.with_label_values(&["stdin"]).inc();
        m.parsed_events.with_label_values(&["ok"]).inc();
        m.enricher_calls.with_label_values(&["lookup", "ok"]).inc();
        m.subscribers_matched.with_label_values(&["s1"]).inc();
        m.deliveries
            .with_label_values(&["s1", "delivered"])
            .inc_by(2);
        m.delivery_latency_seconds
            .with_label_values(&["s1"])
            .observe(0.012);
        m.dlq_depth.with_label_values(&["s1"]).set(5);

        let text = String::from_utf8(m.render()).unwrap();
        for needle in [
            "pwrelay_build_info",
            "pwrelay_ready",
            "pwrelay_source_lines_total",
            "pwrelay_parsed_events_total",
            "pwrelay_enricher_calls_total",
            "pwrelay_subscribers_matched_total",
            "pwrelay_deliveries_total",
            "pwrelay_delivery_latency_seconds",
            "pwrelay_dlq_depth",
        ] {
            assert!(
                text.contains(needle),
                "expected metric {needle} in output:\n{text}"
            );
        }
    }
}
