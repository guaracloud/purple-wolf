//! Admin HTTP server: /healthz, /readyz, /metrics, /version.
//!
//! Bound on a separate address from any subscriber endpoints; intended
//! for cluster-internal scrape only. Authentication on the admin
//! surface is a v0.4 concern — for v0.3, bind to an internal CIDR.

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
pub async fn serve(
    addr: SocketAddr,
    metrics: Arc<Metrics>,
    shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    serve_listener(listener, metrics, shutdown).await
}

/// Same as `serve` but takes an already-bound listener — useful for
/// tests that want to pre-bind on port 0 and read the resolved port.
pub async fn serve_listener(
    listener: TcpListener,
    metrics: Arc<Metrics>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let bound = listener.local_addr()?;
    tracing::info!(addr = %bound, "admin server listening");

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
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let metrics = metrics.clone();
                        async move { Ok::<_, Infallible>(route(req, metrics).await) }
                    });
                    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                        tracing::debug!(error = %e, peer = %peer, "admin connection closed");
                    }
                });
            }
        }
    }
}

async fn route(req: Request<Incoming>, metrics: Arc<Metrics>) -> Response<Full<Bytes>> {
    let path = req.uri().path();
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

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
        let handle = tokio::spawn(serve_listener(listener, m, shutdown_rx));

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
}
