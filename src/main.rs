mod config;
mod detectors;
mod ffi;
mod observe;
mod policy;
mod proxy;
mod request_model;
mod rules;

use crate::config::Config;
use crate::detectors::injection::InjectionDetector;
use crate::detectors::reputation::ReputationDetector;
use crate::detectors::signatures::SignatureDetector;
use crate::detectors::structural::StructuralDetector;
use crate::detectors::{Detector, Engine};
use crate::proxy::AppState;
use crate::rules::Rules;
use axum::routing::any;
use axum::Router;
use notify::{RecursiveMode, Watcher};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().with_env_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "info".into()),
    ).init();

    let config_path = PathBuf::from(
        std::env::var("PURPLE_WOLF_CONFIG").unwrap_or_else(|_| "config/purple-wolf.toml".into()),
    );
    let text = std::fs::read_to_string(&config_path).expect("config file must exist");
    let cfg: Config = Config::parse(&text).expect("config must parse");
    let listen: SocketAddr = cfg.listen.parse().expect("listen must be a socket addr");

    let detectors: Vec<Box<dyn Detector>> = vec![
        Box::new(InjectionDetector),
        Box::new(SignatureDetector::new()),
        Box::new(StructuralDetector),
        Box::new(ReputationDetector::new(100, vec![])),
    ];
    let rules = Arc::new(Rules::new(cfg, config_path.clone()));

    // Hot-reload watcher: re-read config on file change.
    let watch_rules = rules.clone();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if res.is_ok() {
            match watch_rules.reload() {
                Ok(()) => tracing::info!("config reloaded"),
                Err(e) => tracing::error!(error = %e, "config reload failed; keeping previous"),
            }
        }
    })
    .expect("watcher must build");
    watcher
        .watch(&config_path, RecursiveMode::NonRecursive)
        .expect("must watch config file");

    let state = AppState {
        rules,
        engine: Arc::new(Engine::new(detectors)),
        http: reqwest::Client::new(),
    };

    // Prometheus metrics on a second listener.
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], 9090))
        .install()
        .expect("metrics exporter must install");

    let app = Router::new()
        .fallback(any(proxy::handle))
        .with_state(state);

    tracing::info!(%listen, "purple-wolf listening");
    let listener = tokio::net::TcpListener::bind(listen).await.expect("bind");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server");
}
