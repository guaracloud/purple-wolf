//! Library surface for `purple-wolf-relay`.
//!
//! The binary in `src/main.rs` is a thin clap wrapper; the actual work
//! (load config, validate, build pipeline, serve admin endpoints, wait
//! for shutdown) lives here so it's testable from integration tests
//! that drive the relay end-to-end without a subprocess.
//!
//! See `docs/webhook-protocol.md` for the on-the-wire envelope contract.

pub mod admin;
pub mod config;
pub mod metrics;
pub mod pipeline;
pub mod sources;

use std::sync::Arc;
use tokio::sync::broadcast;

/// Options passed from the CLI / library caller. Decoupled from clap's
/// `Args` struct so embedding the relay in another binary (or a test
/// harness) doesn't have to drag clap along.
#[derive(Debug, Clone)]
pub struct RunOpts {
    /// Path to the YAML/JSON config file.
    pub config_path: std::path::PathBuf,
    /// If true, load + validate the config and exit `Ok(())` without
    /// starting the pipeline.
    pub validate_only: bool,
    /// `host:port` for the admin server (/metrics, /healthz, /readyz,
    /// /version).
    pub admin_addr: String,
}

/// Load config, validate, and (unless `validate_only`) run the pipeline
/// until SIGINT/SIGTERM. Admin server and pipeline are spawned on a
/// shared broadcast shutdown channel; the first ctrl_c (or SIGTERM, on
/// Unix) sends the shutdown signal to both.
pub async fn run(opts: RunOpts) -> anyhow::Result<()> {
    let cfg = config::load_from_file(&opts.config_path)?;
    let resolved = config::validate(&cfg)?;
    if opts.validate_only {
        tracing::info!(path = %opts.config_path.display(), "config OK");
        return Ok(());
    }

    let metrics = Arc::new(metrics::Metrics::new()?);
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    let admin_addr: std::net::SocketAddr = opts
        .admin_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("admin_addr {:?}: {e}", opts.admin_addr))?;

    let admin_handle = tokio::spawn(admin::serve(
        admin_addr,
        metrics.clone(),
        shutdown_tx.subscribe(),
    ));
    let pipeline_handle = tokio::spawn(pipeline::run(
        resolved,
        metrics.clone(),
        shutdown_tx.subscribe(),
    ));

    wait_for_signal().await;
    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(());

    // Both tasks listen on the broadcast — join in parallel and log
    // anything that didn't go cleanly.
    let (a, p) = tokio::join!(admin_handle, pipeline_handle);
    log_task_outcome("admin", a);
    log_task_outcome("pipeline", p);
    Ok(())
}

fn log_task_outcome(name: &str, outcome: Result<anyhow::Result<()>, tokio::task::JoinError>) {
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(task = name, error = %e, "task returned error"),
        Err(e) => tracing::warn!(task = name, error = %e, "task join failure"),
    }
}

#[cfg(unix)]
async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("got SIGTERM"),
        _ = sigint.recv()  => tracing::info!("got SIGINT"),
    }
}

#[cfg(not(unix))]
async fn wait_for_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
