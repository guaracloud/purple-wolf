//! Pipeline runtime: orchestrates sources → parser/enrich → fan-out
//! → per-subscriber sinks as a tokio task graph.
//!
//! Topology:
//!
//! ```text
//! N source tasks  →  mpsc<RawEvent>(1024)
//!                        ↓
//!                parser + enrich task
//!                        ↓
//!                  fan-out task
//!                        ↓
//!   N per-subscriber mpsc<Envelope>(subscriber_queue) → N sink tasks
//! ```
//!
//! Backpressure policy: if a subscriber's per-subscriber mpsc is
//! full, the fan-out task DROPS the event for THAT subscriber (and
//! counts it in metrics). It never blocks the fan-out — protecting
//! fast subscribers from a slow one. Fast-path: if `try_send` is
//! `Ok`, we keep going; only when the channel is full do we fall
//! into the drop branch.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

use crate::config::Resolved;
use crate::envelope::{Envelope, EnvelopeSource};
use crate::metrics::Metrics;
use crate::parser::{parse_line, ParseError};
use crate::sources::{self, RawEvent};
use crate::subscribers::filter::CompiledFilter;
use crate::subscribers::http::{config_from, run_sink, HttpSinkConfig};

const SOURCE_CHANNEL_CAP: usize = 1024;

pub async fn run(
    resolved: Resolved,
    metrics: Arc<Metrics>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let instance_id = resolved.instance_id.clone();
    let subscriber_queue = resolved.raw.relay.subscriber_queue;

    tracing::info!(
        instance_id = %instance_id,
        sources = resolved.raw.sources.len(),
        enrichers = resolved.raw.enrichments.len(),
        subscribers = resolved.raw.subscribers.len(),
        subscriber_queue,
        "pipeline starting"
    );

    // Build enrichers (Arc so they can be shared if multiple parser
    // tasks ever exist; today there's just one).
    let enrichers: Vec<_> = resolved
        .raw
        .enrichments
        .iter()
        .map(crate::enrichers::build)
        .collect();

    // Build subscribers: one per-subscriber mpsc + tokio task running
    // run_sink. Disabled subscribers are skipped — their slot doesn't
    // exist in the fan-out vector.
    let mut subs: Vec<PerSubscriber> = Vec::new();
    for s in &resolved.raw.subscribers {
        if !s.enabled {
            tracing::info!(subscriber_id = %s.id, "subscriber disabled; skipping");
            continue;
        }
        let secret = resolved
            .subscriber_secrets
            .get(&s.id)
            .expect("validated config guarantees a secret per subscriber")
            .to_vec();
        let dlq = Arc::new(crate::subscribers::dlq::Dlq::new(1000));
        let cfg: HttpSinkConfig = config_from(s, secret, dlq);
        let (tx, rx) = mpsc::channel::<Envelope>(subscriber_queue);
        let filter = CompiledFilter::compile(&s.filter);
        let id = cfg.id.clone();
        let sink_shutdown = shutdown.resubscribe();
        let sink_handle = tokio::spawn(run_sink(cfg, rx, sink_shutdown));
        subs.push(PerSubscriber {
            id,
            filter,
            tx,
            sink_handle,
        });
    }

    // Single mpsc all source tasks feed.
    let (raw_tx, mut raw_rx) = mpsc::channel::<RawEvent>(SOURCE_CHANNEL_CAP);

    let mut source_handles = Vec::new();
    for sc in &resolved.raw.sources {
        let source = match sources::build(sc) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "failed to build source");
                continue;
            }
        };
        let tx = raw_tx.clone();
        let sd = shutdown.resubscribe();
        source_handles.push(tokio::spawn(async move {
            if let Err(e) = source.run(tx, sd).await {
                tracing::error!(error = %e, "source task ended with error");
            }
        }));
    }
    // Drop our own clone of raw_tx so the parser exits naturally when
    // every source closes.
    drop(raw_tx);

    // Mark pipeline ready once subscriber tasks are up. /readyz uses
    // this to flip from 503 → 200.
    metrics.ready.set(1);

    // Parser + enrich + fan-out loop. Single task today; trivial to
    // scale to N parser tasks if profiling ever points there.
    let parser_metrics = metrics.clone();
    let parser_handle = tokio::spawn({
        let mut subs = subs;
        let instance_id = instance_id.clone();
        let enrichers = enrichers;
        let enricher_timeout = Duration::from_millis(500);
        let mut shutdown_rx = shutdown.resubscribe();
        async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.recv() => {
                        tracing::info!("pipeline parser shutting down");
                        break;
                    }
                    msg = raw_rx.recv() => {
                        let Some(raw) = msg else {
                            tracing::info!("all sources closed; pipeline draining");
                            break;
                        };
                        process_one(&raw, &enrichers, enricher_timeout, &instance_id, &mut subs, &parser_metrics).await;
                    }
                }
            }
            // Best-effort drop of sub.tx clones happens when the loop
            // exits — sink tasks then drain or shut down on their own.
            drop(subs);
        }
    });

    // Wait for shutdown.
    let _ = shutdown.recv().await;
    tracing::info!("pipeline received shutdown");
    metrics.ready.set(0);

    // Source tasks listen on the same broadcast; they're already in
    // shutdown. Wait briefly for them.
    for h in source_handles {
        let _ = tokio::time::timeout(Duration::from_secs(5), h).await;
    }
    // Parser/fan-out:
    let _ = tokio::time::timeout(Duration::from_secs(5), parser_handle).await;

    tracing::info!("pipeline stopped");
    Ok(())
}

async fn process_one(
    raw: &RawEvent,
    enrichers: &[Arc<dyn crate::enrichers::Enricher>],
    enricher_timeout: Duration,
    instance_id: &str,
    subs: &mut [PerSubscriber],
    _metrics: &Arc<Metrics>,
) {
    let parsed = match parse_line(&raw.line) {
        Ok(p) => p,
        Err(ParseError::NotPurpleWolf) => return,
        Err(e) => {
            tracing::warn!(error = %e, "parse error");
            return;
        }
    };
    let mut event = parsed.event;
    // Promote event.labels → envelope.labels (the WAF emits operator
    // labels under "labels" in the audit JSON; the protocol spec
    // places them at the envelope top level so subscribers don't have
    // to chase them inside `event`).
    let labels = take_labels(&mut event);

    let mut labels = labels;
    for enricher in enrichers {
        enricher.enrich(&mut labels, enricher_timeout).await;
    }

    let env = Envelope::new(
        event,
        EnvelopeSource {
            middleware: parsed.middleware,
            router: parsed.router,
            entry_point: parsed.entry_point,
            relay_instance: instance_id.to_string(),
        },
        labels,
    );

    fan_out(&env, subs).await;
}

/// Pull `labels` out of the parsed audit JSON into a `BTreeMap`.
/// The audit emits a flat string→string object; anything else is
/// dropped (a malformed labels field in audit-log JSON shouldn't take
/// down delivery for the rest of the event).
fn take_labels(event: &mut serde_json::Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(obj) = event.as_object_mut() {
        if let Some(serde_json::Value::Object(map)) = obj.remove("labels") {
            for (k, v) in map {
                if let serde_json::Value::String(s) = v {
                    out.insert(k, s);
                }
            }
        }
    }
    out
}

struct PerSubscriber {
    id: String,
    filter: CompiledFilter,
    tx: mpsc::Sender<Envelope>,
    #[allow(dead_code)]
    sink_handle: tokio::task::JoinHandle<()>,
}

async fn fan_out(env: &Envelope, subs: &mut [PerSubscriber]) {
    for sub in subs.iter_mut() {
        if !sub.filter.matches(env) {
            continue;
        }
        // Non-blocking try_send so a slow subscriber's full queue
        // can't backpressure the fan-out. Drop + count on full.
        match sub.tx.try_send(env.clone()) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    subscriber_id = %sub.id,
                    event_id = %env.event_id,
                    "subscriber queue full; dropping event"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    subscriber_id = %sub.id,
                    event_id = %env.event_id,
                    "subscriber channel closed; dropping event"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_labels_promotes_string_map() {
        let mut v = serde_json::json!({
            "labels": {"tenant": "acme", "service": "checkout"},
            "action": "block"
        });
        let labels = take_labels(&mut v);
        assert_eq!(labels.get("tenant").map(String::as_str), Some("acme"));
        assert_eq!(labels.get("service").map(String::as_str), Some("checkout"));
        // event should no longer carry labels (they live at the
        // envelope's top level per protocol spec).
        assert!(v.get("labels").is_none());
        assert_eq!(v["action"], "block");
    }

    #[test]
    fn take_labels_handles_missing() {
        let mut v = serde_json::json!({"action": "block"});
        let labels = take_labels(&mut v);
        assert!(labels.is_empty());
    }

    #[test]
    fn take_labels_drops_non_string_values() {
        let mut v = serde_json::json!({
            "labels": {"tenant": "acme", "count": 42, "nested": {"x": 1}}
        });
        let labels = take_labels(&mut v);
        assert_eq!(labels.len(), 1, "non-string values must be dropped");
        assert_eq!(labels.get("tenant").map(String::as_str), Some("acme"));
    }
}
