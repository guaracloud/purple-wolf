use crate::config::{Config, FailMode, OverCap};
use crate::detectors::{Engine, Group};
use crate::observe::{self, AuditEntry};
use crate::policy::{self, Action, Decision};
use crate::request_model::RequestView;
use crate::rules::Rules;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, Response, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

/// Shared state handed to every request.
#[derive(Clone)]
pub struct AppState {
    pub rules: Arc<Rules>,
    pub engine: Arc<Engine>,
    pub http: reqwest::Client,
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

    // Buffer the body up to the inspection cap.
    let (body_bytes, body_inspected) = read_body(body, cfg.body.max_inspect_bytes).await;
    if body_bytes.is_none() && cfg.body.over_cap == OverCap::Block {
        return blocked_response("body exceeds inspection cap");
    }
    let raw_body = body_bytes.clone().unwrap_or_default();

    let view = RequestView::build(
        &method, &host, &path, &raw_query, headers.clone(),
        raw_body.to_vec(), body_inspected, peer.ip(),
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
        tracing::warn!(target: "audit", entry = %serde_json::to_string(&entry).unwrap_or_default());
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
        Action::Allow => forward(&state.http, &cfg, &parts, raw_body).await,
    }
}

/// Read the body, capped. Returns (Some(bytes), true) if fully read within the
/// cap, or (None, false) if it exceeded the cap.
async fn read_body(body: Body, cap: usize) -> (Option<Bytes>, bool) {
    match axum::body::to_bytes(body, cap).await {
        Ok(b) => (Some(b), true),
        Err(_) => (None, false),
    }
}

/// Forward an allowed request to the configured `localhost` upstream.
async fn forward(
    client: &reqwest::Client,
    cfg: &Config,
    parts: &axum::http::request::Parts,
    body: Bytes,
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
        if k.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(k.as_str(), v.as_bytes());
    }
    match builder.send().await {
        Ok(resp) => {
            let status = StatusCode::from_u16(resp.status().as_u16())
                .unwrap_or(StatusCode::BAD_GATEWAY);
            let bytes = resp.bytes().await.unwrap_or_default();
            let mut out = Response::new(Body::from(bytes));
            *out.status_mut() = status;
            out
        }
        Err(_) => {
            let mut out = Response::new(Body::from("upstream unreachable"));
            *out.status_mut() = StatusCode::BAD_GATEWAY;
            out
        }
    }
}

fn blocked_response(reason: &str) -> Response<Body> {
    let mut out = Response::new(Body::from(reason.to_string()));
    *out.status_mut() = StatusCode::FORBIDDEN;
    out
}
