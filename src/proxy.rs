use crate::config::{Config, FailMode, OverCap};
use crate::detectors::{Engine, Group};
use crate::observe::{self, AuditEntry};
use crate::policy::{self, Action, Decision};
use crate::request_model::RequestView;
use crate::rules::Rules;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use futures_util::{Stream, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

/// Shared state handed to every request.
#[derive(Clone)]
pub struct AppState {
    pub rules: Arc<Rules>,
    pub engine: Arc<Engine>,
    pub http: reqwest::Client,
}

/// A boxed stream of body chunks, used to forward an oversized body without
/// ever buffering it whole.
type ChunkStream =
    std::pin::Pin<Box<dyn Stream<Item = Result<Bytes, axum::Error>> + Send>>;

/// Outcome of incrementally reading the request body.
enum BodyRead {
    /// Whole body fits within the inspection cap.
    Buffered(Bytes),
    /// Body exceeds the cap. `prefix` is what was read so far; `rest` is the
    /// not-yet-consumed remainder of the stream. Chaining them reconstructs
    /// the complete original body for forwarding.
    OverCap { prefix: Vec<u8>, rest: ChunkStream },
    /// A genuine read error occurred mid-body.
    Error,
}

/// Axum handler: inspect the request, then block or forward to the upstream.
pub async fn handle(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response<Body> {
    let started = Instant::now();
    let cfg = state.rules.current();

    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let raw_query = parts.uri.query().unwrap_or("").to_string();
    let method = parts.method.as_str().to_string();
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
        .collect();
    let host = parts
        .headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Incrementally read the body up to the inspection cap.
    let read = read_body(body, cfg.body.max_inspect_bytes).await;

    // `inspect_body` is the bytes handed to detectors; `forward_body` is the
    // (possibly streaming) body sent upstream. `body_inspected` tells the
    // detectors whether `inspect_body` is the complete request body.
    let (inspect_body, body_inspected, forward_body): (Vec<u8>, bool, reqwest::Body) =
        match read {
            BodyRead::Buffered(bytes) => {
                (bytes.to_vec(), true, reqwest::Body::from(bytes))
            }
            BodyRead::OverCap { prefix, rest } => match cfg.body.over_cap {
                OverCap::Block => return blocked_response("body exceeds inspection cap"),
                OverCap::Pass => {
                    // Forward the complete original body by streaming the
                    // already-read prefix chained with the remainder.
                    let prefix_chunk =
                        futures_util::stream::once(async move { Ok(Bytes::from(prefix)) });
                    let full = prefix_chunk.chain(rest);
                    (Vec::new(), false, reqwest::Body::wrap_stream(full))
                }
            },
            BodyRead::Error => {
                // Soft failure: a mid-body read error means the body bytes are
                // gone, so we cannot forward even on fail_open.
                metrics::counter!("purple_wolf_soft_failures_total").increment(1);
                match cfg.fail_mode {
                    FailMode::FailClosed => {
                        return blocked_response("inspection failed (fail_closed)")
                    }
                    FailMode::FailOpen => return bad_gateway("body read error"),
                }
            }
        };

    let source_ip = client_ip(&parts.headers, peer.ip());
    let view = RequestView::build(
        &method, &host, &path, &raw_query, headers.clone(),
        inspect_body, body_inspected, source_ip,
    );

    // Inspect, isolating any detector panic per request.
    let enabled = state.rules.enabled_groups(&cfg, &view.host, &view.path);
    let inspect = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.engine.inspect(&view, &enabled)
    }));

    let decision = match inspect {
        Ok(verdicts) => {
            let rules = state.rules.clone();
            let cfg2 = cfg.clone();
            let host = view.host.clone();
            let path = view.path.clone();
            policy::decide(verdicts, cfg.mode, move |g: Group| {
                rules.group_mode(&cfg2, g, &host, &path)
            })
        }
        Err(_) => {
            // Soft failure: apply fail mode.
            metrics::counter!("purple_wolf_soft_failures_total").increment(1);
            match cfg.fail_mode {
                FailMode::FailClosed => {
                    return blocked_response("inspection failed (fail_closed)")
                }
                FailMode::FailOpen => Decision {
                    action: Action::Allow, blocked_by: None, would_block: vec![],
                },
            }
        }
    };

    // Audit log + metrics.
    let entry = AuditEntry::from(&view, &decision);
    if entry.is_noteworthy() {
        observe::log_audit(&entry);
    }
    let hits: Vec<&str> = decision
        .would_block
        .iter()
        .chain(decision.blocked_by.iter())
        .map(|v| v.group.as_str())
        .collect();
    observe::record_request(decision.action, &hits, started.elapsed().as_micros() as f64);

    match decision.action {
        Action::Block => blocked_response("request blocked by purple-wolf"),
        Action::Allow => forward(&state.http, &cfg, &parts, forward_body).await,
    }
}

/// Incrementally read the body up to `cap` bytes.
///
/// - Returns `Buffered` if the whole body is `<= cap`.
/// - Returns `OverCap` (carrying the read prefix plus the unconsumed stream)
///   once the accumulated size exceeds `cap`, without buffering the rest.
/// - Returns `Error` on a mid-body read error.
async fn read_body(body: Body, cap: usize) -> BodyRead {
    let mut stream = body.into_data_stream();
    let mut prefix: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                prefix.extend_from_slice(&bytes);
                if prefix.len() > cap {
                    let rest: ChunkStream = Box::pin(stream);
                    return BodyRead::OverCap { prefix, rest };
                }
            }
            Err(_) => return BodyRead::Error,
        }
    }
    BodyRead::Buffered(Bytes::from(prefix))
}

/// Forward an allowed request to the configured `localhost` upstream. `body`
/// may be a buffered `Bytes` or a streaming body — both are `reqwest::Body`.
async fn forward(
    client: &reqwest::Client,
    cfg: &Config,
    parts: &axum::http::request::Parts,
    body: reqwest::Body,
) -> Response<Body> {
    let url = format!(
        "{}{}",
        cfg.upstream.trim_end_matches('/'),
        parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    );
    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(method, &url).body(body);
    for (k, v) in parts.headers.iter() {
        // Skip hop-by-hop / framing headers: reqwest sets its own.
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_bytes());
    }
    match builder.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            // Capture upstream response headers BEFORE consuming the body —
            // otherwise the headers map disappears with the response object.
            let upstream_headers = resp.headers().clone();
            // Stream the upstream body end-to-end so a multi-GB response
            // never lands in our memory.
            let stream = resp.bytes_stream();
            let mut out = Response::new(Body::from_stream(stream));
            *out.status_mut() = status;
            copy_response_headers(&upstream_headers, out.headers_mut());
            out
        }
        Err(e) => {
            metrics::counter!("purple_wolf_upstream_errors_total").increment(1);
            tracing::warn!(error = %e, "upstream forward failed");
            bad_gateway("upstream unreachable")
        }
    }
}

/// Copy upstream response headers to the downstream response, skipping
/// hop-by-hop / framing headers. Converts between `reqwest::header` and
/// `axum::http` header types via `from_bytes` — both crates use `http` 1.x
/// underneath, but going through the bytes representation keeps us
/// future-proof against minor type divergence.
fn copy_response_headers(src: &reqwest::header::HeaderMap, dst: &mut HeaderMap) {
    for (k, v) in src.iter() {
        if is_hop_by_hop(k.as_str()) {
            continue;
        }
        let name = match HeaderName::from_bytes(k.as_ref()) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let value = match HeaderValue::from_bytes(v.as_bytes()) {
            Ok(v) => v,
            Err(_) => continue,
        };
        dst.append(name, value);
    }
}

/// True for headers that must not be forwarded verbatim — reqwest manages
/// framing itself, and the upstream's `Host` differs from the client's.
fn is_hop_by_hop(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("connection")
}

/// Derive the client source IP. In the sidecar topology the TCP peer is
/// always the local proxy (loopback), so we honour standard L7 headers
/// before falling back to the transport-level peer:
///
/// 1. First parseable, comma-separated entry of `X-Forwarded-For`.
/// 2. `X-Real-IP`.
/// 3. The TCP peer.
pub fn client_ip(headers: &HeaderMap, peer: IpAddr) -> IpAddr {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for part in v.split(',') {
            if let Ok(ip) = part.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    if let Some(ip) = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }
    peer
}

fn blocked_response(reason: &str) -> Response<Body> {
    let mut out = Response::new(Body::from(reason.to_string()));
    *out.status_mut() = StatusCode::FORBIDDEN;
    out
}

fn bad_gateway(reason: &str) -> Response<Body> {
    let mut out = Response::new(Body::from(reason.to_string()));
    *out.status_mut() = StatusCode::BAD_GATEWAY;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic request body of `n` zero bytes.
    fn body_of(n: usize) -> Body {
        Body::from(Bytes::from(vec![0u8; n]))
    }

    fn peer() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    #[test]
    fn client_ip_uses_xff_single() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        assert_eq!(client_ip(&h, peer()), "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_uses_xff_leftmost_parseable_with_spaces() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static(" 203.0.113.7 , 10.0.0.1 , 10.0.0.2"),
        );
        assert_eq!(client_ip(&h, peer()), "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_falls_through_xff_garbage_to_next_valid() {
        let mut h = HeaderMap::new();
        h.insert(
            "x-forwarded-for",
            HeaderValue::from_static("not-an-ip, 198.51.100.5"),
        );
        assert_eq!(client_ip(&h, peer()), "198.51.100.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_uses_x_real_ip_when_no_xff() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("198.51.100.9"));
        assert_eq!(client_ip(&h, peer()), "198.51.100.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_falls_back_to_peer_when_no_headers() {
        let h = HeaderMap::new();
        assert_eq!(client_ip(&h, peer()), peer());
    }

    #[test]
    fn client_ip_falls_back_to_peer_when_both_unparseable() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("not-an-ip"));
        h.insert("x-real-ip", HeaderValue::from_static("also-not"));
        assert_eq!(client_ip(&h, peer()), peer());
    }

    #[tokio::test]
    async fn under_cap_is_buffered() {
        match read_body(body_of(10), 100).await {
            BodyRead::Buffered(b) => assert_eq!(b.len(), 10),
            _ => panic!("expected Buffered"),
        }
    }

    #[tokio::test]
    async fn exactly_at_cap_is_buffered() {
        // `> cap` is the over-cap trigger, so a body equal to the cap buffers.
        match read_body(body_of(100), 100).await {
            BodyRead::Buffered(b) => assert_eq!(b.len(), 100),
            _ => panic!("expected Buffered at exactly the cap"),
        }
    }

    #[tokio::test]
    async fn over_cap_is_classified_and_reconstructs_full_body() {
        let read = read_body(body_of(250), 100).await;
        let (prefix, rest) = match read {
            BodyRead::OverCap { prefix, rest } => (prefix, rest),
            _ => panic!("expected OverCap"),
        };
        assert!(prefix.len() > 100, "prefix must exceed the cap");
        // Chaining prefix + rest must recover all 250 original bytes.
        let mut total = prefix.len();
        let mut stream = rest;
        while let Some(chunk) = stream.next().await {
            total += chunk.expect("no read error in test body").len();
        }
        assert_eq!(total, 250);
    }
}
