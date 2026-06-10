//! Admin HTTP server: /healthz, /readyz, /metrics, /version.
//!
//! Bound on a separate address from any subscriber endpoints; intended
//! for cluster-internal scrape only. Optional bearer auth protects data
//! and metadata endpoints while keeping probe endpoints open.

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use crate::metrics::Metrics;

/// Serve the admin endpoints until `shutdown` fires. Binds a TCP
/// listener on `addr` and delegates to `serve_listener`.
///
/// `auth_token` is the optional bearer token guarding the admin surface.
/// `None` leaves the endpoints open (the original default) — callers should log
/// a startup warning in that case so the open surface is a conscious choice.
pub async fn serve(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    auth_token: Option<Arc<String>>,
    shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener(listener, metrics, auth_token, shutdown).await
}

/// Same as `serve` but takes an already-bound listener — useful for
/// tests that want to pre-bind on port 0 and read the resolved port.
pub async fn serve_listener(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    auth_token: Option<Arc<String>>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let bound = listener.local_addr()?;
    tracing::info!(addr = %bound, auth = auth_token.is_some(), "admin server listening");

    loop {
        tokio::select! {
            biased;
            _ = shutdown.recv() => {
                tracing::info!("admin server shutting down");
                return Ok(());
            }
            accept = listener.accept() => {
                let (stream, peer) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!(error = %e, "admin accept failed");
                        continue;
                    }
                };
                let io = TokioIo::new(stream);
                let metrics = metrics.clone();
                let auth_token = auth_token.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let metrics = metrics.clone();
                        let auth_token = auth_token.clone();
                        async move { Ok::<_, Infallible>(route(req, metrics, auth_token).await) }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        tracing::debug!(error = %e, peer = %peer, "admin connection closed");
                    }
                });
            }
        }
    }
}

async fn route(
    req: Request<Incoming>,
    metrics: Arc<Metrics>,
    auth_token: Option<Arc<String>>,
) -> Response<Full<Bytes>> {
    // Probe endpoints must never require auth: orchestrator health/readiness
    // checks carry no bearer token, and a 401 would make the relay look dead
    // or permanently unready. Data/metadata endpoints remain gated.
    let path = req.uri().path();
    if path != "/healthz" && path != "/readyz" {
        let header = req
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if !is_authorized(auth_token.as_deref().map(String::as_str), header) {
            return json(StatusCode::UNAUTHORIZED, br#"{"error":"unauthorized"}"#);
        }
    }
    match path {
        "/healthz" => json(StatusCode::OK, br#"{"status":"ok"}"#),
        "/readyz" => {
            // Wired against the metrics gauge that the pipeline flips
            // in Phase G Task 23. Until then this reports 503 because
            // no pipeline runs in Task 9.
            if metrics.ready.get() == 1 {
                json(StatusCode::OK, br#"{"status":"ready"}"#)
            } else {
                json(
                    StatusCode::SERVICE_UNAVAILABLE,
                    br#"{"status":"not_ready","reason":"pipeline_not_running"}"#,
                )
            }
        }
        "/metrics" => {
            let body = metrics.render();
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain; version=0.0.4")
                .body(Full::new(Bytes::from(body)))
                .expect("static response")
        }
        "/version" => {
            let v = env!("CARGO_PKG_VERSION");
            let sha = option_env!("PURPLE_WOLF_RELAY_GIT_SHA").unwrap_or("unknown");
            let body = format!(r#"{{"version":"{v}","git_sha":"{sha}"}}"#);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .expect("static response")
        }
        _ => json(StatusCode::NOT_FOUND, br#"{"error":"not found"}"#),
    }
}

fn json(status: StatusCode, body: &'static [u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(body)))
        .expect("static response")
}

/// Decide whether an admin request is authorized.
///
/// - `configured`: the operator-set bearer token, or `None` when admin auth
///   is disabled (the default — preserves the original open behavior).
/// - `auth_header`: the request's `Authorization` header value, if present.
///
/// When a token is configured, the header must be exactly `Bearer <token>`.
/// The token comparison is constant-time to avoid leaking the secret through
/// response-timing differences.
fn is_authorized(configured: Option<&str>, auth_header: Option<&str>) -> bool {
    let Some(expected) = configured else {
        return true; // auth disabled
    };
    let Some(header) = auth_header else {
        return false;
    };
    let Some(presented) = header.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(presented.as_bytes(), expected.as_bytes())
}

/// Constant-time byte-slice equality. Returns false fast on length mismatch
/// (length is not secret), then compares all bytes without early exit so the
/// time taken does not depend on how many leading bytes matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[test]
    fn authorized_when_no_token_configured() {
        // Default (no token) preserves the original open behavior: any request is
        // authorized. The startup warning (logged elsewhere) tells operators
        // to front it with an authenticated proxy or set a token.
        assert!(is_authorized(None, None));
        assert!(is_authorized(None, Some("Bearer anything")));
    }

    #[test]
    fn rejects_when_token_configured_but_header_missing_or_wrong() {
        let token = "s3cret-token";
        assert!(!is_authorized(Some(token), None), "missing header → 401");
        assert!(
            !is_authorized(Some(token), Some("Bearer wrong")),
            "wrong token → 401"
        );
        assert!(
            !is_authorized(Some(token), Some("s3cret-token")),
            "missing 'Bearer ' scheme → 401"
        );
        assert!(
            !is_authorized(Some(token), Some("Bearer s3cret-token-extra")),
            "token must match exactly, not by prefix"
        );
    }

    #[test]
    fn accepts_correct_bearer_token() {
        assert!(is_authorized(
            Some("s3cret-token"),
            Some("Bearer s3cret-token")
        ));
    }

    /// Smoke test: bind a listener on port 0, drive each admin endpoint
    /// with reqwest, assert expected status codes. The pipeline isn't
    /// running so /readyz must return 503 with `pipeline_not_running` —
    /// that's the contract that lets ops alert on the relay failing
    /// to come up.
    #[tokio::test]
    async fn admin_endpoints_respond() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();

        let m = metrics.clone();
        let handle = tokio::spawn(serve_listener(listener, m, None, shutdown_rx));

        // Server is already listening — no sleep needed.
        let client = reqwest::Client::new();
        let base = format!("http://{}", bound);

        let r = client.get(format!("{base}/healthz")).send().await.unwrap();
        assert_eq!(r.status(), 200);

        let r = client.get(format!("{base}/readyz")).send().await.unwrap();
        assert_eq!(r.status(), 503);
        assert!(r.text().await.unwrap().contains("pipeline_not_running"));

        let r = client.get(format!("{base}/metrics")).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert!(r.text().await.unwrap().contains("pwrelay_build_info"));

        let v = client.get(format!("{base}/version")).send().await.unwrap();
        assert_eq!(v.status(), 200);
        assert!(v.text().await.unwrap().contains(env!("CARGO_PKG_VERSION")));

        let r = client.get(format!("{base}/bogus")).send().await.unwrap();
        assert_eq!(r.status(), 404);

        // Graceful shutdown.
        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("admin server didn't shut down in time")
            .expect("admin task panicked");
    }

    /// With a token configured, /metrics requires a correct bearer token but
    /// /healthz stays open for liveness probes.
    #[tokio::test]
    async fn admin_auth_gates_protected_endpoints() {
        let metrics = Arc::new(Metrics::new().unwrap());
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let token = Arc::new("top-secret".to_string());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bound = listener.local_addr().unwrap();
        let handle = tokio::spawn(serve_listener(
            listener,
            metrics.clone(),
            Some(token),
            shutdown_rx,
        ));

        let client = reqwest::Client::new();
        let base = format!("http://{}", bound);

        // Liveness is always open.
        let r = client.get(format!("{base}/healthz")).send().await.unwrap();
        assert_eq!(r.status(), 200, "healthz must stay open for probes");

        // No token → 401 on a protected endpoint.
        let r = client.get(format!("{base}/metrics")).send().await.unwrap();
        assert_eq!(r.status(), 401, "metrics without token must be 401");

        // Readiness is probe-safe: Kubernetes readiness checks do not carry
        // bearer tokens, so /readyz must not be auth-gated even when admin
        // auth protects metrics and version metadata.
        let r = client.get(format!("{base}/readyz")).send().await.unwrap();
        assert_eq!(
            r.status(),
            503,
            "readyz must report pipeline readiness, not admin auth"
        );

        // Wrong token → 401.
        let r = client
            .get(format!("{base}/metrics"))
            .header("authorization", "Bearer nope")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);

        // Correct token → 200.
        let r = client
            .get(format!("{base}/metrics"))
            .header("authorization", "Bearer top-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "metrics with correct token must be 200");

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("admin server didn't shut down in time")
            .expect("admin task panicked");
    }
}
