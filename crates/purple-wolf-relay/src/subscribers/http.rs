//! HTTP subscriber sink.
//!
//! Each subscriber owns a tokio task running this `run_sink` loop:
//! pull `Envelope`s from a bounded mpsc, sign each, POST with the
//! per-subscriber timeout, classify the response, and either ack
//! (drop), retry with backoff, or move to the DLQ.
//!
//! Retry classification follows docs/webhook-protocol.md:
//!
//! - `2xx` — delivered, done.
//! - `4xx` except `408` / `429` — permanent failure, DLQ.
//! - `408` / `429` / `5xx` / network / timeout — retryable.
//! - `3xx` — relay never follows redirects; treated as permanent
//!   failure.
//!
//! Per-retry the envelope's `delivery_id`, `delivered_at`, and HMAC
//! `X-PurpleWolf-Timestamp` all roll — the timestamp is part of the
//! HMAC input (anti-replay), so re-signing per attempt is mandatory.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

use crate::config::SubscriberConfig;
use crate::envelope::Envelope;
use crate::metrics::Metrics;
use crate::signer::Signer;
use crate::subscribers::dlq::Dlq;
use crate::subscribers::retry::RetrySchedule;

/// One subscriber's runtime state, shared between the fan-out (which
/// pushes envelopes) and the admin server (which may want to inspect
/// the DLQ).
pub struct SubscriberRuntime {
    pub id: String,
    pub dlq: Arc<Dlq>,
    pub tx: mpsc::Sender<Envelope>,
}

/// Per-task settings, passed into `run_sink` once at task spawn so the
/// hot path doesn't re-read config.
pub struct HttpSinkConfig {
    pub id: String,
    pub url: String,
    pub timeout: Duration,
    pub retry: RetrySchedule,
    pub max_attempts: u32,
    pub signer: Signer,
    pub dlq: Arc<Dlq>,
    pub metrics: Option<Arc<Metrics>>,
}

/// Outcome of one delivery attempt, classified per the protocol spec.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AttemptOutcome {
    Delivered,
    Retryable,
    PermanentFailure,
}

pub(crate) fn classify_status(status: u16) -> AttemptOutcome {
    match status {
        200..=299 => AttemptOutcome::Delivered,
        408 | 429 | 500..=599 => AttemptOutcome::Retryable,
        _ => AttemptOutcome::PermanentFailure,
    }
}

/// The user-agent header sent on every webhook POST. Centralized so
/// subscribers can deny-list us by UA if needed (per the protocol
/// recommendations).
pub const USER_AGENT: &str = concat!("purple-wolf-relay/", env!("CARGO_PKG_VERSION"));

/// Spawn-friendly runner. Returns when `rx` closes or `shutdown` fires.
pub async fn run_sink(
    cfg: HttpSinkConfig,
    mut rx: mpsc::Receiver<Envelope>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let client = reqwest::Client::builder()
        .timeout(cfg.timeout)
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none()) // 3xx is a failure
        .build()
        .expect("reqwest client build");

    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => {
                tracing::info!(subscriber = %cfg.id, "subscriber sink shutting down");
                return;
            }
            env = rx.recv() => {
                let Some(env) = env else {
                    tracing::info!(subscriber = %cfg.id, "subscriber input closed");
                    return;
                };
                deliver_with_retries(&cfg, &client, env).await;
            }
        }
    }
}

async fn deliver_with_retries(
    cfg: &HttpSinkConfig,
    client: &reqwest::Client,
    initial_env: Envelope,
) {
    let mut env = initial_env;
    let mut attempt: u32 = 1;
    loop {
        let outcome = attempt_one(cfg, client, &env, attempt).await;
        match outcome {
            AttemptOutcome::Delivered => {
                bump_outcome(cfg, "delivered");
                tracing::info!(
                    subscriber = %cfg.id,
                    event_id = %env.event_id,
                    attempt,
                    "delivered"
                );
                return;
            }
            AttemptOutcome::PermanentFailure => {
                bump_outcome(cfg, "dlq");
                update_dlq_depth(cfg);
                tracing::warn!(
                    subscriber = %cfg.id,
                    event_id = %env.event_id,
                    attempt,
                    "permanent failure; sending to DLQ"
                );
                cfg.dlq.push(env);
                update_dlq_depth(cfg);
                return;
            }
            AttemptOutcome::Retryable => {
                if attempt >= cfg.max_attempts {
                    bump_outcome(cfg, "dlq");
                    tracing::warn!(
                        subscriber = %cfg.id,
                        event_id = %env.event_id,
                        attempt,
                        max_attempts = cfg.max_attempts,
                        "max_attempts exhausted; sending to DLQ"
                    );
                    cfg.dlq.push(env);
                    update_dlq_depth(cfg);
                    return;
                }
                bump_outcome(cfg, "retry");
                let delay = cfg.retry.next_delay(attempt);
                tracing::warn!(
                    subscriber = %cfg.id,
                    event_id = %env.event_id,
                    attempt,
                    next_attempt_in_ms = delay.as_millis() as u64,
                    "retryable failure; backing off"
                );
                tokio::time::sleep(delay).await;
                attempt += 1;
                env = env.with_attempt(attempt);
            }
        }
    }
}

fn bump_outcome(cfg: &HttpSinkConfig, outcome: &str) {
    if let Some(m) = &cfg.metrics {
        m.deliveries
            .with_label_values(&[cfg.id.as_str(), outcome])
            .inc();
    }
}

fn update_dlq_depth(cfg: &HttpSinkConfig) {
    if let Some(m) = &cfg.metrics {
        m.dlq_depth
            .with_label_values(&[cfg.id.as_str()])
            .set(cfg.dlq.len() as i64);
    }
}

async fn attempt_one(
    cfg: &HttpSinkConfig,
    client: &reqwest::Client,
    env: &Envelope,
    attempt: u32,
) -> AttemptOutcome {
    let body = match serde_json::to_vec(env) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(
                subscriber = %cfg.id,
                event_id = %env.event_id,
                error = %e,
                "envelope serialization failed; dropping (permanent)"
            );
            return AttemptOutcome::PermanentFailure;
        }
    };
    let timestamp = chrono::Utc::now().timestamp() as u64;
    let signature = cfg.signer.sign(timestamp, &body);

    let req = client
        .post(&cfg.url)
        .header("content-type", "application/json")
        .header("x-purplewolf-schema", crate::envelope::SCHEMA_V1)
        .header("x-purplewolf-event-id", &env.event_id)
        .header("x-purplewolf-delivery-id", &env.delivery_id)
        .header("x-purplewolf-attempt", attempt.to_string())
        .header("x-purplewolf-timestamp", timestamp.to_string())
        .header("x-purplewolf-signature", signature)
        .body(body);

    let start = std::time::Instant::now();
    let result = match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            classify_status(status)
        }
        Err(e) => {
            // Distinguish timeout from connect/IO errors only for log
            // verbosity; both classify the same way (retryable).
            if e.is_timeout() {
                tracing::warn!(
                    subscriber = %cfg.id,
                    event_id = %env.event_id,
                    attempt,
                    "delivery timed out"
                );
            } else {
                tracing::warn!(
                    subscriber = %cfg.id,
                    event_id = %env.event_id,
                    attempt,
                    error = %e,
                    "delivery network error"
                );
            }
            AttemptOutcome::Retryable
        }
    };
    if let Some(m) = &cfg.metrics {
        let elapsed = start.elapsed().as_secs_f64();
        m.delivery_latency_seconds
            .with_label_values(&[cfg.id.as_str()])
            .observe(elapsed);
    }
    result
}

/// Construct the static parts of an `HttpSinkConfig` from a
/// `SubscriberConfig` + the resolved secret. The DLQ is supplied by
/// the caller so the admin server can hold a strong reference for
/// inspection.
pub fn config_from(
    s: &SubscriberConfig,
    secret: Vec<u8>,
    dlq: Arc<Dlq>,
    metrics: Option<Arc<Metrics>>,
) -> HttpSinkConfig {
    HttpSinkConfig {
        id: s.id.clone(),
        url: s.url.clone(),
        timeout: Duration::from_millis(s.timeout_ms),
        retry: RetrySchedule::from_config(&s.retry),
        max_attempts: s.retry.max_attempts,
        signer: Signer::new(secret),
        dlq,
        metrics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Envelope, EnvelopeSource};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn env() -> Envelope {
        Envelope::new(
            serde_json::json!({"action": "block", "would_block_rules": []}),
            EnvelopeSource {
                middleware: Some("strict-waf".into()),
                router: Some("checkout".into()),
                entry_point: Some("web".into()),
                relay_instance: "r1".into(),
            },
            BTreeMap::from([("tenant".into(), "acme".into())]),
        )
    }

    fn sink_config(url: String, max_attempts: u32) -> HttpSinkConfig {
        HttpSinkConfig {
            id: "test".into(),
            url,
            timeout: Duration::from_secs(1),
            retry: RetrySchedule::from_config(&crate::config::RetryConfig {
                max_attempts,
                base_delay_ms: 10,
                max_delay_ms: 100,
            }),
            max_attempts,
            signer: Signer::new(b"test-secret".to_vec()),
            dlq: Arc::new(Dlq::new(16)),
            metrics: None,
        }
    }

    #[test]
    fn classify_status_partitions_responses_correctly() {
        assert_eq!(classify_status(200), AttemptOutcome::Delivered);
        assert_eq!(classify_status(204), AttemptOutcome::Delivered);
        assert_eq!(classify_status(299), AttemptOutcome::Delivered);
        assert_eq!(classify_status(301), AttemptOutcome::PermanentFailure);
        assert_eq!(classify_status(400), AttemptOutcome::PermanentFailure);
        assert_eq!(classify_status(401), AttemptOutcome::PermanentFailure);
        assert_eq!(classify_status(404), AttemptOutcome::PermanentFailure);
        assert_eq!(classify_status(408), AttemptOutcome::Retryable);
        assert_eq!(classify_status(429), AttemptOutcome::Retryable);
        assert_eq!(classify_status(500), AttemptOutcome::Retryable);
        assert_eq!(classify_status(502), AttemptOutcome::Retryable);
        assert_eq!(classify_status(599), AttemptOutcome::Retryable);
        assert_eq!(classify_status(600), AttemptOutcome::PermanentFailure);
    }

    #[tokio::test]
    async fn delivers_on_2xx() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&mock)
            .await;

        let cfg = sink_config(mock.uri(), 3);
        let dlq = cfg.dlq.clone();
        let (tx, rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = broadcast::channel::<()>(1);
        let h = tokio::spawn(run_sink(cfg, rx, sd_rx));

        tx.send(env()).await.unwrap();
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        assert!(dlq.is_empty());
    }

    #[tokio::test]
    async fn retries_on_500_then_succeeds() {
        let mock = MockServer::start().await;
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                let n = c.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    ResponseTemplate::new(500)
                } else {
                    ResponseTemplate::new(200)
                }
            })
            .mount(&mock)
            .await;

        let cfg = sink_config(mock.uri(), 5);
        let dlq = cfg.dlq.clone();
        let (tx, rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = broadcast::channel::<()>(1);
        let h = tokio::spawn(run_sink(cfg, rx, sd_rx));

        tx.send(env()).await.unwrap();
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        assert!(
            dlq.is_empty(),
            "delivered on the third try; DLQ stays empty"
        );
    }

    #[tokio::test]
    async fn permanent_4xx_goes_to_dlq_without_retry() {
        let mock = MockServer::start().await;
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                c.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(400)
            })
            .mount(&mock)
            .await;

        let cfg = sink_config(mock.uri(), 5);
        let dlq = cfg.dlq.clone();
        let (tx, rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = broadcast::channel::<()>(1);
        let h = tokio::spawn(run_sink(cfg, rx, sd_rx));

        tx.send(env()).await.unwrap();
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1, "no retries on 4xx");
        assert_eq!(dlq.len(), 1);
    }

    #[tokio::test]
    async fn exhausts_max_attempts_then_dlq() {
        let mock = MockServer::start().await;
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();
        Mock::given(method("POST"))
            .respond_with(move |_: &wiremock::Request| {
                c.fetch_add(1, Ordering::SeqCst);
                ResponseTemplate::new(503)
            })
            .mount(&mock)
            .await;

        let cfg = sink_config(mock.uri(), 3);
        let dlq = cfg.dlq.clone();
        let (tx, rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = broadcast::channel::<()>(1);
        let h = tokio::spawn(run_sink(cfg, rx, sd_rx));

        tx.send(env()).await.unwrap();
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
        assert_eq!(
            counter.load(Ordering::SeqCst),
            3,
            "exactly max_attempts tries"
        );
        assert_eq!(dlq.len(), 1);
    }

    #[tokio::test]
    async fn signature_changes_per_attempt() {
        // Capture the headers from each request the subscriber gets.
        // Because the HMAC input includes the timestamp, signature
        // values for attempts 1..N must all differ.
        let mock = MockServer::start().await;
        let received = Arc::new(std::sync::Mutex::new(Vec::<(String, String)>::new()));
        let r = received.clone();
        Mock::given(method("POST"))
            .respond_with(move |req: &wiremock::Request| {
                let mut g = r.lock().unwrap();
                let sig = req
                    .headers
                    .get("x-purplewolf-signature")
                    .map(|v| v.to_str().unwrap_or("").to_string())
                    .unwrap_or_default();
                let ts = req
                    .headers
                    .get("x-purplewolf-timestamp")
                    .map(|v| v.to_str().unwrap_or("").to_string())
                    .unwrap_or_default();
                g.push((sig, ts));
                if g.len() < 3 {
                    ResponseTemplate::new(500)
                } else {
                    ResponseTemplate::new(200)
                }
            })
            .mount(&mock)
            .await;

        let cfg = HttpSinkConfig {
            id: "test".into(),
            url: mock.uri(),
            timeout: Duration::from_secs(1),
            retry: RetrySchedule::from_config(&crate::config::RetryConfig {
                max_attempts: 5,
                base_delay_ms: 1_100, // ensure ≥1s between attempts
                max_delay_ms: 2_000,
            }),
            max_attempts: 5,
            signer: Signer::new(b"test-secret".to_vec()),
            dlq: Arc::new(Dlq::new(16)),
            metrics: None,
        };
        let (tx, rx) = mpsc::channel(8);
        let (_sd_tx, sd_rx) = broadcast::channel::<()>(1);
        let h = tokio::spawn(run_sink(cfg, rx, sd_rx));

        tx.send(env()).await.unwrap();
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(10), h).await;

        let g = received.lock().unwrap();
        assert_eq!(g.len(), 3);
        // Each timestamp is in the X-PurpleWolf-Timestamp header and is
        // part of the HMAC input — they must all differ across the
        // three attempts (the test sleeps ≥1s between attempts).
        assert_ne!(g[0].1, g[1].1);
        assert_ne!(g[1].1, g[2].1);
        // And therefore signatures differ too.
        assert_ne!(g[0].0, g[1].0);
        assert_ne!(g[1].0, g[2].0);
    }
}
