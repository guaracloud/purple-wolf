//! Configuration types parsed from TOML or JSON.
use serde::Deserialize;

/// Global WAF behavior switch: log-only or block-and-log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Log detections but allow all requests through.
    Monitor,
    /// Block requests when a detector fires in enforce mode.
    Enforce,
}

/// Action taken when the WAF itself encounters an internal error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Allow the request through on internal error (fail-open).
    FailOpen,
    /// Block the request on internal error (fail-closed).
    FailClosed,
}

/// Per-group enforcement level, overriding the global mode for one detector group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupMode {
    /// Block matching requests (subject to the global `Mode`).
    Enforce,
    /// Log but never block, regardless of the global `Mode`.
    Monitor,
    /// Disable this group entirely; detections are skipped.
    Off,
}

/// Policy applied when a request body exceeds `max_inspect_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverCap {
    /// Allow the request even though the body was not fully inspected.
    Pass,
    /// Block the request when the body exceeds the inspection limit.
    Block,
}

/// Body-inspection size limit and over-cap policy.
#[derive(Debug, Clone, Deserialize)]
pub struct BodyConfig {
    /// Maximum body bytes to inspect; bytes beyond this limit are ignored.
    pub max_inspect_bytes: usize,
    /// Action when the body is larger than `max_inspect_bytes`.
    pub over_cap: OverCap,
}

/// Per-group enable flag and enforcement mode.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupConfig {
    /// Whether this detector group is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Enforcement mode for this group, overriding the global mode.
    #[serde(default = "default_group_mode")]
    pub mode: GroupMode,
}

fn default_true() -> bool {
    true
}
fn default_group_mode() -> GroupMode {
    GroupMode::Enforce
}

/// Per-group configuration, one entry for each built-in detector group.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Groups {
    /// Configuration for the injection detector group.
    #[serde(default)]
    pub injection: Option<GroupConfig>,
    /// Configuration for the signatures detector group.
    #[serde(default)]
    pub signatures: Option<GroupConfig>,
    /// Configuration for the structural detector group.
    #[serde(default)]
    pub structural: Option<GroupConfig>,
    /// Configuration for the reputation detector group.
    #[serde(default)]
    pub reputation: Option<GroupConfig>,
}

/// Reputation-detector tuning. Lives in the top-level config because it
/// shapes detector construction at process start; per-request behaviour
/// is governed by the group's mode in `[groups.reputation]`.
#[derive(Debug, Clone, Deserialize)]
pub struct ReputationConfig {
    /// Maximum requests per second allowed from a single source IP.
    #[serde(default = "default_reputation_per_second")]
    pub per_second: u32,
    /// IP addresses that are always blocked regardless of rate.
    #[serde(default)]
    pub deny_list: Vec<String>,
}

fn default_reputation_per_second() -> u32 {
    100
}

impl Default for ReputationConfig {
    fn default() -> ReputationConfig {
        ReputationConfig {
            per_second: default_reputation_per_second(),
            deny_list: Vec::new(),
        }
    }
}

/// Top-level WAF configuration parsed from TOML or JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Global enforcement mode applied to all detector groups.
    pub mode: Mode,
    /// Action to take when the WAF encounters an internal error.
    pub fail_mode: FailMode,
    /// Body-inspection size limit and over-cap policy.
    pub body: BodyConfig,
    /// Per-group enable and mode overrides.
    #[serde(default)]
    pub groups: Groups,
    /// Reputation detector tuning (rate limit and deny list).
    #[serde(default)]
    pub reputation: ReputationConfig,
}

impl Config {
    /// Parse a TOML configuration string.
    pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
    }

    /// Parse a JSON configuration byte slice.
    /// This is the canonical input format for the Traefik middleware plugin.
    pub fn parse_json(bytes: &[u8]) -> Result<Config, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_config() {
        let text = r#"
            mode = "monitor"
            fail_mode = "fail_open"
            [body]
            max_inspect_bytes = 1048576
            over_cap = "pass"
            [groups.injection]
            enabled = true
            mode = "enforce"
        "#;
        let cfg = Config::parse(text).expect("should parse");
        assert_eq!(cfg.mode, Mode::Monitor);
        assert_eq!(cfg.fail_mode, FailMode::FailOpen);
        assert_eq!(cfg.body.max_inspect_bytes, 1048576);
        assert!(cfg.groups.injection.is_some());
    }

    #[test]
    fn defaults_reputation_section_when_absent() {
        let text = r#"
            mode = "monitor"
            fail_mode = "fail_open"
            [body]
            max_inspect_bytes = 1024
            over_cap = "pass"
        "#;
        let cfg = Config::parse(text).expect("should parse");
        assert_eq!(cfg.reputation.per_second, 100);
        assert!(cfg.reputation.deny_list.is_empty());
    }

    #[test]
    fn parses_minimal_toml() {
        let text = r#"
            mode = "enforce"
            fail_mode = "fail_closed"
            [body]
            max_inspect_bytes = 512
            over_cap = "block"
        "#;
        let cfg = Config::parse(text).expect("minimal TOML should parse");
        assert_eq!(cfg.mode, Mode::Enforce);
        assert_eq!(cfg.fail_mode, FailMode::FailClosed);
        assert_eq!(cfg.body.max_inspect_bytes, 512);
        assert!(matches!(cfg.body.over_cap, OverCap::Block));
    }

    #[test]
    fn parses_minimal_json() {
        let json = br#"{
            "mode": "monitor",
            "fail_mode": "fail_open",
            "body": {
                "max_inspect_bytes": 4096,
                "over_cap": "pass"
            }
        }"#;
        let cfg = Config::parse_json(json).expect("minimal JSON should parse");
        assert_eq!(cfg.mode, Mode::Monitor);
        assert_eq!(cfg.fail_mode, FailMode::FailOpen);
        assert_eq!(cfg.body.max_inspect_bytes, 4096);
        assert!(matches!(cfg.body.over_cap, OverCap::Pass));
        // Defaults apply
        assert_eq!(cfg.reputation.per_second, 100);
        assert!(cfg.reputation.deny_list.is_empty());
    }

    #[test]
    fn reputation_section_parses() {
        // TOML form
        let toml_text = r#"
            mode = "enforce"
            fail_mode = "fail_closed"
            [body]
            max_inspect_bytes = 1024
            over_cap = "pass"
            [reputation]
            per_second = 25
            deny_list = ["10.0.0.1", "203.0.113.5"]
        "#;
        let cfg = Config::parse(toml_text).expect("TOML with reputation should parse");
        assert_eq!(cfg.reputation.per_second, 25);
        assert_eq!(cfg.reputation.deny_list, vec!["10.0.0.1", "203.0.113.5"]);

        // JSON form
        let json = br#"{
            "mode": "enforce",
            "fail_mode": "fail_closed",
            "body": {"max_inspect_bytes": 1024, "over_cap": "pass"},
            "reputation": {"per_second": 25, "deny_list": ["10.0.0.1", "203.0.113.5"]}
        }"#;
        let cfg_json = Config::parse_json(json).expect("JSON with reputation should parse");
        assert_eq!(cfg_json.reputation.per_second, 25);
        assert_eq!(
            cfg_json.reputation.deny_list,
            vec!["10.0.0.1", "203.0.113.5"]
        );
    }
}
