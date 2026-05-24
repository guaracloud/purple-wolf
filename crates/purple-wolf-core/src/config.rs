use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Monitor,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    FailOpen,
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupMode {
    Enforce,
    Monitor,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverCap {
    Pass,
    Block,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BodyConfig {
    pub max_inspect_bytes: usize,
    pub over_cap: OverCap,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroupConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_group_mode")]
    pub mode: GroupMode,
}

fn default_true() -> bool { true }
fn default_group_mode() -> GroupMode { GroupMode::Enforce }

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Groups {
    #[serde(default)]
    pub injection: Option<GroupConfig>,
    #[serde(default)]
    pub signatures: Option<GroupConfig>,
    #[serde(default)]
    pub structural: Option<GroupConfig>,
    #[serde(default)]
    pub reputation: Option<GroupConfig>,
}

/// Reputation-detector tuning. Lives in the top-level config because it
/// shapes detector construction at process start; per-request behaviour
/// is governed by the group's mode in `[groups.reputation]`.
#[derive(Debug, Clone, Deserialize)]
pub struct ReputationConfig {
    #[serde(default = "default_reputation_per_second")]
    pub per_second: u32,
    #[serde(default)]
    pub deny_list: Vec<String>,
}

fn default_reputation_per_second() -> u32 { 100 }

impl Default for ReputationConfig {
    fn default() -> ReputationConfig {
        ReputationConfig { per_second: default_reputation_per_second(), deny_list: Vec::new() }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub mode: Mode,
    pub fail_mode: FailMode,
    pub body: BodyConfig,
    #[serde(default)]
    pub groups: Groups,
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
        assert_eq!(cfg_json.reputation.deny_list, vec!["10.0.0.1", "203.0.113.5"]);
    }
}
