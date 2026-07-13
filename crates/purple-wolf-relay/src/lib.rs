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
pub mod enrichers;
pub mod envelope;
pub mod metrics;
pub mod parser;
pub mod pipeline;
pub mod signer;
pub mod sources;
pub mod subscribers;

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
/// until SIGINT/SIGTERM or finite sources reach EOF. Admin server and pipeline
/// are supervised on a shared broadcast shutdown channel; a signal or an
/// unexpected task failure stops the counterpart and the error is propagated.
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

    // Extract the admin token before `resolved` is moved into the pipeline.
    // `None` leaves the admin surface open — warn so it's a conscious choice.
    let admin_token = resolved
        .admin_token
        .as_ref()
        .map(|t| std::sync::Arc::new(t.to_string()));
    if admin_token.is_none() {
        tracing::warn!(
            "admin surface ({admin_addr}) has no auth token (set relay.admin_token_env / \
             admin_token_file, or bind to an internal network / front with an authenticated \
             proxy); /metrics, /readyz, /version are reachable by anyone who can connect"
        );
    }

    let mut admin_handle = tokio::spawn(admin::serve(
        admin_addr,
        metrics.clone(),
        admin_token,
        shutdown_tx.subscribe(),
    ));
    let mut pipeline_handle = tokio::spawn(pipeline::run(
        resolved,
        metrics.clone(),
        shutdown_tx.subscribe(),
    ));

    type TaskOutcome = Result<anyhow::Result<()>, tokio::task::JoinError>;
    enum Stop {
        Signal(anyhow::Result<()>),
        Admin(TaskOutcome),
        Pipeline(TaskOutcome),
    }

    let stop = tokio::select! {
        signal = wait_for_signal() => Stop::Signal(signal),
        outcome = &mut admin_handle => Stop::Admin(outcome),
        outcome = &mut pipeline_handle => Stop::Pipeline(outcome),
    };

    match stop {
        Stop::Signal(signal_result) => {
            tracing::info!("shutdown signal received");
            let _ = shutdown_tx.send(());
            let (admin_outcome, pipeline_outcome) = tokio::join!(admin_handle, pipeline_handle);
            signal_result?;
            task_outcome("admin", admin_outcome)?;
            task_outcome("pipeline", pipeline_outcome)
        }
        Stop::Admin(admin_outcome) => {
            tracing::error!("admin task stopped before shutdown");
            let admin_result = task_outcome("admin", admin_outcome);
            let _ = shutdown_tx.send(());
            let pipeline_result = task_outcome("pipeline", pipeline_handle.await);
            admin_result?;
            pipeline_result?;
            anyhow::bail!("admin task stopped unexpectedly")
        }
        Stop::Pipeline(pipeline_outcome) => {
            let pipeline_result = task_outcome("pipeline", pipeline_outcome);
            if let Err(error) = &pipeline_result {
                tracing::error!(%error, "pipeline task failed; stopping relay");
            } else {
                tracing::info!("pipeline completed; stopping admin server");
            }
            let _ = shutdown_tx.send(());
            let admin_result = task_outcome("admin", admin_handle.await);
            pipeline_result?;
            admin_result
        }
    }
}

fn task_outcome(
    name: &str,
    outcome: Result<anyhow::Result<()>, tokio::task::JoinError>,
) -> anyhow::Result<()> {
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(anyhow::anyhow!("{name} task failed: {error:#}")),
        Err(error) => Err(anyhow::anyhow!("{name} task join failure: {error}")),
    }
}

#[cfg(unix)]
async fn wait_for_signal() -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())
        .map_err(|error| anyhow::anyhow!("install SIGTERM handler: {error}"))?;
    let mut sigint = signal(SignalKind::interrupt())
        .map_err(|error| anyhow::anyhow!("install SIGINT handler: {error}"))?;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("got SIGTERM"),
        _ = sigint.recv()  => tracing::info!("got SIGINT"),
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_signal() -> anyhow::Result<()> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|error| anyhow::anyhow!("install or wait for ctrl-c handler: {error}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn run_propagates_source_failure_without_waiting_for_a_signal() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let missing = dir.path().join("missing-traefik.log");
        let quoted_path =
            serde_json::to_string(&missing.to_string_lossy()).expect("path should serialize");
        let config_path = dir.path().join("relay.yaml");
        std::fs::write(
            &config_path,
            format!("sources:\n  - type: log_tail\n    path: {quoted_path}\nsubscribers: []\n"),
        )
        .expect("config should be written");

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            run(RunOpts {
                config_path,
                validate_only: false,
                admin_addr: "127.0.0.1:0".to_string(),
            }),
        )
        .await
        .expect("relay must not hang after pipeline failure")
        .expect_err("missing source file must fail the relay");

        assert!(error.to_string().contains("source"), "error: {error:#}");
    }
}
