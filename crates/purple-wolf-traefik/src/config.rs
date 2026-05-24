//! Adapt the JSON delivered by Traefik (Middleware plugin params, camelCase)
//! to `purple_wolf_core::config::Config` (snake_case).
use purple_wolf_core::config as core;
use serde::Deserialize;

/// camelCase wrapper for `core::FailMode` whose variants need camelCase spelling
/// ("failOpen" / "failClosed") rather than the snake_case the core enum expects.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum WireFailMode {
    FailOpen,
    FailClosed,
}

impl From<WireFailMode> for core::FailMode {
    fn from(w: WireFailMode) -> Self {
        match w {
            WireFailMode::FailOpen => core::FailMode::FailOpen,
            WireFailMode::FailClosed => core::FailMode::FailClosed,
        }
    }
}

/// camelCase wrapper for `core::ReputationConfig` whose fields use camelCase
/// keys ("perSecond", "denyList") rather than the snake_case the core struct
/// expects.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireReputation {
    #[serde(default = "default_per_second")]
    per_second: u32,
    #[serde(default)]
    deny_list: Vec<String>,
}

fn default_per_second() -> u32 { 100 }

impl Default for WireReputation {
    fn default() -> Self {
        WireReputation { per_second: default_per_second(), deny_list: Vec::new() }
    }
}

impl From<WireReputation> for core::ReputationConfig {
    fn from(w: WireReputation) -> Self {
        core::ReputationConfig { per_second: w.per_second, deny_list: w.deny_list }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Wire {
    mode: core::Mode,
    #[serde(default = "default_fail_mode")]
    fail_mode: WireFailMode,
    #[serde(default)]
    body: WireBody,
    #[serde(default)]
    groups: core::Groups,
    #[serde(default)]
    reputation: WireReputation,
}

fn default_fail_mode() -> WireFailMode { WireFailMode::FailOpen }

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireBody {
    #[serde(default = "default_max_inspect_bytes")]
    max_inspect_bytes: usize,
    #[serde(default = "default_over_cap")]
    over_cap: core::OverCap,
}

fn default_max_inspect_bytes() -> usize { 1_048_576 }
fn default_over_cap() -> core::OverCap { core::OverCap::Pass }

impl Default for WireBody {
    fn default() -> Self {
        WireBody { max_inspect_bytes: default_max_inspect_bytes(), over_cap: default_over_cap() }
    }
}

/// Parse the raw JSON bytes Traefik hands the plugin.
pub fn parse(bytes: &[u8]) -> Result<core::Config, String> {
    let w: Wire = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    Ok(core::Config {
        mode: w.mode,
        fail_mode: w.fail_mode.into(),
        body: core::BodyConfig { max_inspect_bytes: w.body.max_inspect_bytes, over_cap: w.body.over_cap },
        groups: w.groups,
        reputation: w.reputation.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_camelcase() {
        let json = br#"{
          "mode": "enforce",
          "failMode": "failClosed",
          "body": { "maxInspectBytes": 2048, "overCap": "block" },
          "groups": {
            "injection":  { "enabled": true, "mode": "enforce" },
            "structural": { "enabled": false, "mode": "monitor" }
          },
          "reputation": { "perSecond": 50, "denyList": ["1.2.3.4"] }
        }"#;
        let cfg = parse(json).expect("parse");
        assert_eq!(cfg.mode, core::Mode::Enforce);
        assert_eq!(cfg.fail_mode, core::FailMode::FailClosed);
        assert_eq!(cfg.body.max_inspect_bytes, 2048);
        assert_eq!(cfg.body.over_cap, core::OverCap::Block);
        assert_eq!(cfg.reputation.per_second, 50);
    }

    #[test]
    fn defaults_when_optional_fields_absent() {
        let json = br#"{ "mode": "monitor" }"#;
        let cfg = parse(json).expect("parse");
        assert_eq!(cfg.fail_mode, core::FailMode::FailOpen);
        assert_eq!(cfg.body.max_inspect_bytes, 1_048_576);
        assert_eq!(cfg.body.over_cap, core::OverCap::Pass);
    }
}
