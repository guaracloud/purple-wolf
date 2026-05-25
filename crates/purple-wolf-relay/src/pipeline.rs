//! Pipeline runtime: orchestrates sources → parser → enrichers →
//! subscribers as a tokio task graph.
//!
//! Task 9 (current) lands a stub `run()` that just announces start /
//! stop and sits on the shutdown signal. Phases D-F wire the real
//! source / parser / fan-out / sink tasks.

use std::sync::Arc;
use tokio::sync::broadcast;

use crate::config::Resolved;
use crate::metrics::Metrics;

/// Run the pipeline until `shutdown` fires. Phase F Task 20 wires the
/// real source / parser / fan-out / subscriber tasks; Task 9 provides
/// just enough of a runtime that the binary stays alive between SIGINT
/// signals so operators can scrape /metrics + /healthz against it.
pub async fn run(
    resolved: Resolved,
    _metrics: Arc<Metrics>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    tracing::info!(
        instance_id = %resolved.instance_id,
        sources = resolved.raw.sources.len(),
        enrichers = resolved.raw.enrichments.len(),
        subscribers = resolved.raw.subscribers.len(),
        "pipeline starting (skeleton — full runtime arrives in Phase F Task 20)"
    );
    for s in &resolved.raw.subscribers {
        tracing::info!(
            subscriber_id = %s.id,
            enabled = s.enabled,
            url = %s.url,
            "subscriber registered"
        );
    }
    let _ = shutdown.recv().await;
    tracing::info!("pipeline shutting down");
    Ok(())
}
