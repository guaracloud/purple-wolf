//! Library surface for `purple-wolf-relay`.
//!
//! The binary in `src/main.rs` is a thin clap wrapper; the actual work
//! (load config, validate, build pipeline, serve admin endpoints, wait
//! for shutdown) lives here so it's testable from integration tests
//! that drive the relay end-to-end without a subprocess.
//!
//! See `docs/webhook-protocol.md` for the on-the-wire envelope contract.

pub mod config;

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
/// until SIGINT/SIGTERM.
pub async fn run(opts: RunOpts) -> anyhow::Result<()> {
    let cfg = config::load_from_file(&opts.config_path)?;
    let _resolved = config::validate(&cfg)?;
    if opts.validate_only {
        tracing::info!(path = %opts.config_path.display(), "config OK");
        return Ok(());
    }
    // Phase C Task 9 wires this; for now the pipeline is a sleeper so
    // the admin server has something to coexist with.
    anyhow::bail!("pipeline runtime not wired yet — see Phase C Task 9");
}
