use crate::config::{Config, GroupConfig, GroupMode};
use crate::detectors::Group;
use arc_swap::ArcSwap;
use std::path::PathBuf;
use std::sync::Arc;

/// Thread-safe holder of the live config, swappable on hot-reload.
pub struct Rules {
    config: ArcSwap<Config>,
    path: PathBuf,
}

impl Rules {
    pub fn new(config: Config, path: PathBuf) -> Rules {
        Rules { config: ArcSwap::from_pointee(config), path }
    }

    pub fn current(&self) -> Arc<Config> {
        self.config.load_full()
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Re-read the config file. On parse error, keep the existing config.
    pub fn reload(&self) -> Result<(), String> {
        let text = std::fs::read_to_string(&self.path).map_err(|e| e.to_string())?;
        let cfg = Config::parse(&text).map_err(|e| e.to_string())?;
        self.config.store(Arc::new(cfg));
        Ok(())
    }

    /// Effective mode for `group` given request `host`/`path`, applying the
    /// group's own config and any matching override (override wins -> Off).
    pub fn group_mode(&self, cfg: &Config, group: Group, host: &str, path: &str) -> GroupMode {
        for ov in &cfg.overrides {
            let host_ok = ov.host.as_deref().is_none_or(|h| h == host);
            let path_ok = ov.path_prefix.as_deref().is_none_or(|p| path.starts_with(p));
            if host_ok && path_ok && ov.disable_groups.iter().any(|g| g == group.as_str()) {
                return GroupMode::Off;
            }
        }
        let gc: Option<&GroupConfig> = match group {
            Group::Injection => cfg.groups.injection.as_ref(),
            Group::Signatures => cfg.groups.signatures.as_ref(),
            Group::Structural => cfg.groups.structural.as_ref(),
            Group::Reputation => cfg.groups.reputation.as_ref(),
        };
        match gc {
            Some(g) if g.enabled => g.mode,
            _ => GroupMode::Off,
        }
    }

    /// Groups whose effective mode is not Off — the set to actually run.
    pub fn enabled_groups(&self, cfg: &Config, host: &str, path: &str) -> Vec<Group> {
        [Group::Injection, Group::Signatures, Group::Structural, Group::Reputation]
            .into_iter()
            .filter(|g| self.group_mode(cfg, *g, host, path) != GroupMode::Off)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(text: &str) -> Config {
        Config::parse(text).unwrap()
    }

    const BASE: &str = r#"
        mode = "enforce"
        fail_mode = "fail_open"
        upstream = "http://127.0.0.1:3000"
        listen = "0.0.0.0:8080"
        [body]
        max_inspect_bytes = 1024
        over_cap = "pass"
        [groups.injection]
        enabled = true
        mode = "enforce"
        [groups.reputation]
        enabled = false
        mode = "monitor"
    "#;

    #[test]
    fn disabled_group_resolves_to_off() {
        let cfg = config(BASE);
        let rules = Rules::new(cfg.clone(), "x.toml".into());
        assert_eq!(rules.group_mode(&cfg, Group::Reputation, "h", "/"), GroupMode::Off);
        assert_eq!(rules.group_mode(&cfg, Group::Injection, "h", "/"), GroupMode::Enforce);
    }

    #[test]
    fn override_disables_group_for_matching_path() {
        let text = format!("{BASE}\n[[overrides]]\nhost = \"api.x\"\npath_prefix = \"/hooks/\"\ndisable_groups = [\"injection\"]");
        let cfg = config(&text);
        let rules = Rules::new(cfg.clone(), "x.toml".into());
        assert_eq!(rules.group_mode(&cfg, Group::Injection, "api.x", "/hooks/stripe"), GroupMode::Off);
        assert_eq!(rules.group_mode(&cfg, Group::Injection, "api.x", "/other"), GroupMode::Enforce);
    }

    #[test]
    fn enabled_groups_excludes_off() {
        let cfg = config(BASE);
        let rules = Rules::new(cfg.clone(), "x.toml".into());
        let groups = rules.enabled_groups(&cfg, "h", "/");
        assert!(groups.contains(&Group::Injection));
        assert!(!groups.contains(&Group::Reputation));
    }

    #[test]
    fn reload_picks_up_valid_change() {
        let dir = std::env::temp_dir().join("pw-rules-test-valid");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        std::fs::write(&path, BASE).unwrap();
        let rules = Rules::new(config(BASE), path.clone());
        assert_eq!(rules.current().mode, crate::config::Mode::Enforce);

        // Rewrite the file with mode = "monitor" and reload.
        let changed = BASE.replace(r#"mode = "enforce""#, r#"mode = "monitor""#);
        std::fs::write(&path, &changed).unwrap();
        rules.reload().expect("valid config should reload");
        assert_eq!(rules.current().mode, crate::config::Mode::Monitor);
    }

    #[test]
    fn reload_keeps_old_config_on_parse_error() {
        let dir = std::env::temp_dir().join("pw-rules-test-bad");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("c.toml");
        std::fs::write(&path, BASE).unwrap();
        let rules = Rules::new(config(BASE), path.clone());

        // Write garbage; reload must fail and leave the old config intact.
        std::fs::write(&path, "this is not valid toml {{{").unwrap();
        let result = rules.reload();
        assert!(result.is_err(), "bad config must produce an error");
        assert_eq!(
            rules.current().mode,
            crate::config::Mode::Enforce,
            "old config must be retained after a failed reload"
        );
    }
}
