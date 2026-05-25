//! Relay configuration schema, loader, and validator.
//!
//! NOTE: this module is intentionally minimal at Task 7. Task 8 fleshes
//! out the full source/enricher/subscriber schema. The current state
//! exists so the `--validate-only` CLI path compiles end-to-end.

use serde::Deserialize;

/// Top-level relay configuration. Expanded in Task 8.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub sources: Vec<serde_yaml::Value>,
    #[serde(default)]
    pub enrichments: Vec<serde_yaml::Value>,
    #[serde(default)]
    pub subscribers: Vec<serde_yaml::Value>,
}

/// Resolved-and-validated config. Holds anything that requires touching
/// the environment (secrets) so the raw `Config` stays loggable without
/// risk of secret exfiltration via debug prints.
#[derive(Debug)]
pub struct Resolved {
    pub raw: Config,
}

/// Load YAML or JSON from disk, picking the parser by extension.
pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    let cfg: Config = match ext {
        "json" => serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing JSON config {}: {e}", path.display()))?,
        // YAML is a superset of JSON, so this also covers .yml.
        _ => serde_yaml::from_str(&text)
            .map_err(|e| anyhow::anyhow!("parsing YAML config {}: {e}", path.display()))?,
    };
    Ok(cfg)
}

/// Validate cross-field invariants and resolve secret references.
/// Task 8 implements the real checks.
pub fn validate(cfg: &Config) -> anyhow::Result<Resolved> {
    if cfg.sources.is_empty() {
        anyhow::bail!("config: at least one source must be configured");
    }
    if cfg.subscribers.is_empty() {
        anyhow::bail!("config: at least one subscriber must be configured");
    }
    // Task 8 turns this into a deep copy/resolve into Resolved fields.
    Ok(Resolved {
        raw: Config {
            sources: cfg.sources.clone(),
            enrichments: cfg.enrichments.clone(),
            subscribers: cfg.subscribers.clone(),
        },
    })
}
