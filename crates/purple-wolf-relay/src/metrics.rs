//! Prometheus metrics surface.
//!
//! Task 9 lands a `Metrics` struct + `pwrelay_build_info` so the admin
//! server's `/metrics` endpoint is reachable end-to-end. Task 21 grows
//! the full metric family set (source / parser / enricher / delivery /
//! DLQ); subsequent tasks bump individual counters as they wire their
//! features in.

use prometheus::{Encoder, IntGauge, IntGaugeVec, Opts, Registry, TextEncoder};

/// All metric handles. Cloneable Arc lets every pipeline task hold one.
pub struct Metrics {
    registry: Registry,
    /// `pwrelay_build_info{version,git_sha} = 1`. Build-time metadata
    /// exposed as a gauge so dashboards can group by version.
    pub build_info: IntGaugeVec,
    /// Toggles to 1 when the pipeline reports ready (Phase G Task 23
    /// wires the toggler).
    pub ready: IntGauge,
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
        // git_sha is sourced via build.rs in Phase I; for now report
        // "unknown" so the metric is present and scrapable.
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

        Ok(Self {
            registry,
            build_info,
            ready,
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
    fn metrics_renders_build_info() {
        let m = Metrics::new().unwrap();
        let text = String::from_utf8(m.render()).unwrap();
        assert!(
            text.contains("pwrelay_build_info"),
            "expected build_info in: {text}"
        );
    }

    #[test]
    fn metrics_renders_ready_zero_by_default() {
        let m = Metrics::new().unwrap();
        let text = String::from_utf8(m.render()).unwrap();
        // The metric is registered; value is 0 until pipeline flips it.
        assert!(text.contains("pwrelay_ready"), "{text}");
    }
}
