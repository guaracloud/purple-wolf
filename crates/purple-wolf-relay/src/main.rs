//! purple-wolf-relay — webhook fan-out for purple-wolf WAF audit events.
//!
//! See `docs/webhook-protocol.md` for the on-the-wire contract; see this
//! crate's README for operational guidance (DLQ replay, secret rotation,
//! metrics scrape).
use clap::Parser;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(name = "purple-wolf-relay", version, about)]
struct Args {
    /// Path to the relay config (YAML or JSON).
    #[arg(short, long, env = "PURPLE_WOLF_RELAY_CONFIG")]
    config: std::path::PathBuf,
    /// Validate config and exit without starting the pipeline.
    #[arg(long)]
    validate_only: bool,
    /// Listen address for /metrics, /healthz, /readyz, /version.
    #[arg(
        long,
        default_value = "0.0.0.0:9090",
        env = "PURPLE_WOLF_RELAY_ADMIN_ADDR"
    )]
    admin_addr: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();
    let args = Args::parse();
    let opts = purple_wolf_relay::RunOpts {
        config_path: args.config,
        validate_only: args.validate_only,
        admin_addr: args.admin_addr,
    };
    match purple_wolf_relay::run(opts).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal");
            ExitCode::FAILURE
        }
    }
}
