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
//!   N per-subscriber mpsc<Arc<Envelope>>(subscriber_queue) → N sink tasks
//! ```
//!
//! Backpressure policy: if a subscriber's per-subscriber mpsc is
//! full, the fan-out task DROPS the event for THAT subscriber (and
//! counts it in metrics). It never blocks the fan-out — protecting
//! fast subscribers from a slow one. Fast-path: if `try_send` is
//! `Ok`, we keep going; only when the channel is full do we fall
//! into the drop branch.

use anyhow::Context as _;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;

use crate::config::Resolved;
use crate::envelope::{Envelope, EnvelopeSource};
use crate::metrics::Metrics;
use crate::parser::{parse_line, ParseError};
use crate::sources::{self, RawEvent};
use crate::subscribers::filter::CompiledFilter;
use crate::subscribers::http::{config_from, run_sink, HttpSinkConfig};

const SOURCE_CHANNEL_CAP: usize = 1024;
const TASK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

enum ParserExit {
    Shutdown,
    SourcesClosed,
}

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
    // tasks ever exist; today there's just one). Names parallel the
    // enrichers vec so metric labels stay aligned without a runtime
    // lookup.
    let enrichers: Vec<_> = resolved
        .raw
        .enrichments
        .iter()
        .map(crate::enrichers::build)
        .collect();
    let enricher_names: Vec<String> = enrichers.iter().map(|e| e.name().to_string()).collect();

    // Build subscribers: one per-subscriber mpsc + tokio task running
    // run_sink. Disabled subscribers are skipped — their slot doesn't
    // exist in the fan-out vector.
    let mut subs: Vec<PerSubscriber> = Vec::new();
    let mut sink_tasks = JoinSet::new();
    for s in &resolved.raw.subscribers {
        if !s.enabled {
            tracing::info!(subscriber_id = %s.id, "subscriber disabled; skipping");
            continue;
        }
        let secret = resolved
            .subscriber_secrets
            .get(&s.id)
            .ok_or_else(|| anyhow::anyhow!("validated subscriber {:?} has no secret", s.id))?
            .to_vec();
        let dlq = Arc::new(crate::subscribers::dlq::Dlq::new(1000));
        let cfg: HttpSinkConfig = config_from(s, secret, dlq, Some(metrics.clone()));
        let (tx, rx) = mpsc::channel::<Arc<Envelope>>(subscriber_queue);
        let filter = CompiledFilter::compile(&s.filter);
        let id = cfg.id.clone();
        let sink_shutdown = shutdown.resubscribe();
        sink_tasks.spawn(run_sink(cfg, rx, sink_shutdown));
        subs.push(PerSubscriber { id, filter, tx });
    }

    // Single mpsc all source tasks feed.
    let (raw_tx, mut raw_rx) = mpsc::channel::<RawEvent>(SOURCE_CHANNEL_CAP);

    let mut source_tasks = JoinSet::new();
    for sc in &resolved.raw.sources {
        let source = sources::build(sc).context("build source")?;
        let source_id = source.id().to_string();
        let tx = raw_tx.clone();
        let sd = shutdown.resubscribe();
        source_tasks.spawn(async move {
            source
                .run(tx, sd)
                .await
                .with_context(|| format!("source {source_id:?} failed"))
        });
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
    let parser_instance_id = instance_id.clone();
    let mut parser_shutdown = shutdown.resubscribe();
    let mut parser_handle = tokio::spawn(async move {
        let mut subs = subs;
        let enricher_timeout = Duration::from_millis(500);
        let exit = loop {
            tokio::select! {
                biased;
                _ = parser_shutdown.recv() => {
                    tracing::info!("pipeline parser shutting down");
                    break ParserExit::Shutdown;
                }
                msg = raw_rx.recv() => {
                    let Some(raw) = msg else {
                        tracing::info!("all sources closed; pipeline draining");
                        break ParserExit::SourcesClosed;
                    };
                    process_one(
                        &raw,
                        &enrichers,
                        &enricher_names,
                        enricher_timeout,
                        &parser_instance_id,
                        &mut subs,
                        &parser_metrics,
                    ).await;
                }
            }
        };
        // Best-effort drop of sub.tx clones happens when the loop
        // exits — sink tasks then drain or shut down on their own.
        drop(subs);
        exit
    });

    // Supervise every source and the parser. A failed source used to be logged
    // inside a detached task while readiness stayed at 1 and the outer relay
    // waited forever for a signal. Normal source completion (stdin EOF) is not
    // an error; the parser drains and exits after the last sender closes.
    let mut parser_finished = false;
    let mut sources_exhausted = false;
    let mut outcome = loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => {
                tracing::info!("pipeline received shutdown");
                break Ok(());
            }
            joined = source_tasks.join_next(), if !source_tasks.is_empty() => {
                match joined {
                    Some(Ok(Ok(()))) => {
                        tracing::info!(remaining = source_tasks.len(), "source task stopped");
                    }
                    Some(Ok(Err(error))) => {
                        tracing::error!(%error, "source task failed");
                        break Err(error);
                    }
                    Some(Err(error)) => {
                        tracing::error!(%error, "source task join failure");
                        break Err(anyhow::anyhow!("source task join failure: {error}"));
                    }
                    None => {}
                }
            }
            joined = sink_tasks.join_next(), if !sink_tasks.is_empty() => {
                match joined {
                    Some(Ok(())) if parser_handle.is_finished() => {
                        tracing::info!(remaining = sink_tasks.len(), "subscriber sink stopped after parser completion");
                    }
                    Some(Ok(())) => {
                        break Err(anyhow::anyhow!("subscriber sink stopped while the parser was active"));
                    }
                    Some(Err(error)) => {
                        tracing::error!(%error, "subscriber sink task join failure");
                        break Err(anyhow::anyhow!("subscriber sink task join failure: {error}"));
                    }
                    None => {}
                }
            }
            joined = &mut parser_handle => {
                parser_finished = true;
                match joined {
                    Ok(exit) => {
                        sources_exhausted = matches!(exit, ParserExit::SourcesClosed);
                        break Ok(())
                    }
                    Err(error) => {
                        tracing::error!(%error, "parser task join failure");
                        break Err(anyhow::anyhow!("parser task join failure: {error}"));
                    }
                }
            }
        }
    };

    metrics.ready.set(0);

    // An error is unrecoverable for this pipeline instance. Abort remaining
    // work immediately; on ordinary shutdown the shared broadcast gives
    // sources time to persist bookmarks and lets the parser exit cleanly.
    if outcome.is_err() {
        source_tasks.abort_all();
        sink_tasks.abort_all();
        if !parser_finished {
            parser_handle.abort();
        }
    }

    match tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, drain_source_tasks(&mut source_tasks)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) if outcome.is_ok() => outcome = Err(error),
        Ok(Err(_)) => {}
        Err(_) => {
            source_tasks.abort_all();
            while source_tasks.join_next().await.is_some() {}
            if outcome.is_ok() {
                outcome = Err(anyhow::anyhow!(
                    "source tasks did not stop within {TASK_SHUTDOWN_TIMEOUT:?}"
                ));
            }
        }
    }

    if !parser_finished {
        match tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, &mut parser_handle).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) if outcome.is_ok() => {
                outcome = Err(anyhow::anyhow!("parser task join failure: {error}"));
            }
            Ok(Err(_)) => {}
            Err(_) => {
                parser_handle.abort();
                let _ = parser_handle.await;
                if outcome.is_ok() {
                    outcome = Err(anyhow::anyhow!(
                        "parser task did not stop within {TASK_SHUTDOWN_TIMEOUT:?}"
                    ));
                }
            }
        }
    }

    // Parser completion after all finite sources close drops every subscriber
    // sender. Let configured HTTP timeouts/retries govern a complete drain;
    // otherwise the top-level supervisor's shutdown broadcast can discard the
    // final queued delivery. Signal/error shutdown remains bounded.
    let sink_result = if sources_exhausted && outcome.is_ok() {
        Ok(drain_sink_tasks(&mut sink_tasks).await)
    } else {
        tokio::time::timeout(TASK_SHUTDOWN_TIMEOUT, drain_sink_tasks(&mut sink_tasks)).await
    };
    match sink_result {
        Ok(Ok(())) => {}
        Ok(Err(error)) if outcome.is_ok() => outcome = Err(error),
        Ok(Err(_)) => {}
        Err(_) => {
            sink_tasks.abort_all();
            while sink_tasks.join_next().await.is_some() {}
            if outcome.is_ok() {
                outcome = Err(anyhow::anyhow!(
                    "subscriber sinks did not stop within {TASK_SHUTDOWN_TIMEOUT:?}"
                ));
            }
        }
    }

    tracing::info!("pipeline stopped");
    outcome
}

async fn drain_source_tasks(source_tasks: &mut JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
    let mut first_error = None;
    while let Some(joined) = source_tasks.join_next().await {
        let error = match joined {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(error) if error.is_cancelled() => None,
            Err(error) => Some(anyhow::anyhow!("source task join failure: {error}")),
        };
        if first_error.is_none() {
            first_error = error;
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn drain_sink_tasks(sink_tasks: &mut JoinSet<()>) -> anyhow::Result<()> {
    while let Some(joined) = sink_tasks.join_next().await {
        if let Err(error) = joined {
            if !error.is_cancelled() {
                return Err(anyhow::anyhow!(
                    "subscriber sink task join failure: {error}"
                ));
            }
        }
    }
    Ok(())
}

async fn process_one(
    raw: &RawEvent,
    enrichers: &[Arc<dyn crate::enrichers::Enricher>],
    enricher_names: &[String],
    enricher_timeout: Duration,
    instance_id: &str,
    subs: &mut [PerSubscriber],
    metrics: &Arc<Metrics>,
) {
    metrics
        .source_lines
        .with_label_values(&[raw.source_id.as_str()])
        .inc();

    let parsed = match parse_line(&raw.line) {
        Ok(p) => {
            metrics.parsed_events.with_label_values(&["ok"]).inc();
            p
        }
        Err(ParseError::NotPurpleWolf) => {
            metrics.parsed_events.with_label_values(&["not_pw"]).inc();
            return;
        }
        Err(e) => {
            metrics.parsed_events.with_label_values(&["error"]).inc();
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
    for (enricher, name) in enrichers.iter().zip(enricher_names.iter()) {
        // Wrap each enricher call in tokio::time::timeout so a runaway
        // enricher can't stall the parser task; the trait contract
        // already says enrichers must not propagate failure, but the
        // belt-and-braces timeout protects against a buggy enricher
        // that ignores the contract.
        let timed = tokio::time::timeout(
            enricher_timeout * 2, // double the per-call budget so the inner timeout fires first
            enricher.enrich(&mut labels, enricher_timeout),
        )
        .await;
        match timed {
            Ok(()) => metrics
                .enricher_calls
                .with_label_values(&[name.as_str(), "ok"])
                .inc(),
            Err(_) => {
                metrics
                    .enricher_calls
                    .with_label_values(&[name.as_str(), "timeout"])
                    .inc();
                tracing::warn!(enricher = %name, "enricher exceeded outer-timeout");
            }
        }
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

    tracing::debug!(
        event_id = %env.event_id,
        labels = ?env.labels,
        middleware = ?env.source.middleware,
        "envelope built; fanning out"
    );

    fan_out(Arc::new(env), subs, metrics).await;
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
    tx: mpsc::Sender<Arc<Envelope>>,
}

async fn fan_out(env: Arc<Envelope>, subs: &mut [PerSubscriber], metrics: &Arc<Metrics>) {
    for sub in subs.iter_mut() {
        if !sub.filter.matches(&env) {
            continue;
        }
        metrics
            .subscribers_matched
            .with_label_values(&[sub.id.as_str()])
            .inc();
        // Non-blocking try_send so a slow subscriber's full queue
        // can't backpressure the fan-out. Drop + count on full.
        match sub.tx.try_send(Arc::clone(&env)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                metrics
                    .deliveries
                    .with_label_values(&[sub.id.as_str(), "dropped_queue_full"])
                    .inc();
                tracing::warn!(
                    subscriber_id = %sub.id,
                    event_id = %env.event_id,
                    "subscriber queue full; dropping event"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                metrics
                    .deliveries
                    .with_label_values(&[sub.id.as_str(), "dropped_channel_closed"])
                    .inc();
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
    use crate::config::SubscriberFilter;
    use crate::envelope::EnvelopeSource;
    use std::sync::Arc;

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

    #[tokio::test]
    async fn fan_out_sends_arc_envelope_to_matching_subscriber() {
        let env = Arc::new(Envelope::new(
            serde_json::json!({"action": "block"}),
            EnvelopeSource {
                middleware: None,
                router: None,
                entry_point: None,
                relay_instance: "r".into(),
            },
            BTreeMap::new(),
        ));
        let event_id = env.event_id.clone();
        let (tx, mut rx) = mpsc::channel(1);
        let mut subs = vec![PerSubscriber {
            id: "sub".into(),
            filter: CompiledFilter::compile(&SubscriberFilter::default()),
            tx,
        }];
        let metrics = Arc::new(Metrics::new().unwrap());

        fan_out(env, &mut subs, &metrics).await;

        let received = rx.recv().await.expect("envelope should be queued");
        assert_eq!(received.event_id, event_id);
    }

    #[tokio::test]
    async fn source_failure_returns_error_and_clears_readiness() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let missing = dir.path().join("missing-traefik.log");
        let quoted_path =
            serde_json::to_string(&missing.to_string_lossy()).expect("path should serialize");
        let cfg = crate::config::load_from_str(&format!(
            "sources:\n  - type: log_tail\n    path: {quoted_path}\nsubscribers: []\n"
        ))
        .expect("config should parse");
        let resolved = crate::config::validate(&cfg).expect("config should validate");
        let metrics = Arc::new(Metrics::new().expect("metrics should initialize"));
        let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            run(resolved, metrics.clone(), shutdown_rx),
        )
        .await
        .expect("pipeline must not hang after an unrecoverable source failure")
        .expect_err("missing source file must fail the pipeline");

        assert!(error.to_string().contains("source"), "error: {error:#}");
        assert_eq!(metrics.ready.get(), 0, "failed pipeline must not be ready");
    }
}
