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

#[derive(Debug, Clone, Deserialize)]
pub struct Override {
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub disable_groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub mode: Mode,
    pub fail_mode: FailMode,
    pub body: BodyConfig,
    #[serde(default)]
    pub groups: Groups,
    #[serde(default)]
    pub overrides: Vec<Override>,
    pub upstream: String,
    pub listen: String,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(text)
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
            upstream = "http://127.0.0.1:3000"
            listen = "0.0.0.0:8080"
            [body]
            max_inspect_bytes = 1048576
            over_cap = "pass"
            [groups.injection]
            enabled = true
            mode = "enforce"
            [[overrides]]
            host = "api.guaracloud.com"
            path_prefix = "/webhooks/"
            disable_groups = ["reputation"]
        "#;
        let cfg = Config::parse(text).expect("should parse");
        assert_eq!(cfg.mode, Mode::Monitor);
        assert_eq!(cfg.fail_mode, FailMode::FailOpen);
        assert_eq!(cfg.body.max_inspect_bytes, 1048576);
        assert_eq!(cfg.overrides.len(), 1);
        assert_eq!(cfg.overrides[0].disable_groups, vec!["reputation"]);
    }
}
