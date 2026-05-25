//! Adapt the JSON delivered by Traefik (Middleware plugin params, camelCase)
//! to `purple_wolf_core::config::Config` (snake_case).
//!
//! ## Traefik primitive stringification
//!
//! When Traefik passes Middleware plugin parameters to a WASM guest, it
//! serializes ALL scalar values as JSON strings — even YAML booleans and
//! integers. A Middleware spec written as
//!
//! ```yaml
//! groups:
//!   injection: { enabled: true, mode: enforce }
//! reputation: { perSecond: 100 }
//! ```
//!
//! arrives at the plugin as `{"enabled":"true","perSecond":"100"}`. Strict
//! serde rejects that ("invalid type: string, expected boolean") and the
//! plugin fails to load. To survive this without forcing every operator to
//! quote-everything, we wrap each scalar field in a permissive deserializer
//! that accepts both the native JSON type and a stringified form.
use purple_wolf_core::config as core;
use serde::de::{Deserializer, Error as _};
use serde::Deserialize;

// ---------- lenient primitive deserializers ----------

/// Accepts a JSON boolean OR a stringified boolean (`"true"` / `"false"`,
/// case-insensitive, with a few common spellings) — Traefik stringifies
/// scalars when forwarding plugin config to the http-wasm guest.
///
/// Empty string is rejected (NEW-M6): an `enabled: ""` is almost always
/// a tenant typo, not a deliberate "off" directive, and silently mapping
/// it to `false` disables the detector with no operator-visible signal.
fn de_lenient_bool<'de, D: Deserializer<'de>>(d: D) -> Result<bool, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        Bool(bool),
        Str(String),
    }
    match V::deserialize(d)? {
        V::Bool(b) => Ok(b),
        V::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            other => Err(D::Error::custom(format!(
                "invalid boolean string {other:?}"
            ))),
        },
    }
}

/// Accepts a JSON number OR a stringified non-negative integer.
fn de_lenient_usize<'de, D: Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        Num(u64),
        Str(String),
    }
    match V::deserialize(d)? {
        V::Num(n) => usize::try_from(n).map_err(|e| D::Error::custom(e.to_string())),
        V::Str(s) => s
            .trim()
            .parse::<usize>()
            .map_err(|e| D::Error::custom(e.to_string())),
    }
}

/// Accepts a JSON number OR a stringified `u32`.
fn de_lenient_u32<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V {
        Num(u64),
        Str(String),
    }
    match V::deserialize(d)? {
        V::Num(n) => u32::try_from(n).map_err(|e| D::Error::custom(e.to_string())),
        V::Str(s) => s
            .trim()
            .parse::<u32>()
            .map_err(|e| D::Error::custom(e.to_string())),
    }
}

// ---------- wire types (mirror core, with camelCase + lenient primitives) ----------

/// camelCase wrapper for `core::FailMode`. Enum variants have no fields so
/// `deny_unknown_fields` doesn't apply here — serde rejects unknown variant
/// strings by default.
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

/// camelCase + lenient-bool wrapper for `core::GroupConfig`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireGroupConfig {
    #[serde(default = "default_true", deserialize_with = "de_lenient_bool")]
    enabled: bool,
    #[serde(default = "default_group_mode")]
    mode: core::GroupMode,
}

fn default_true() -> bool {
    true
}
fn default_group_mode() -> core::GroupMode {
    core::GroupMode::Enforce
}

impl From<WireGroupConfig> for core::GroupConfig {
    fn from(w: WireGroupConfig) -> Self {
        core::GroupConfig {
            enabled: w.enabled,
            mode: w.mode,
        }
    }
}

/// camelCase wrapper for `core::Groups`.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireGroups {
    #[serde(default)]
    injection: Option<WireGroupConfig>,
    #[serde(default)]
    signatures: Option<WireGroupConfig>,
    #[serde(default)]
    structural: Option<WireGroupConfig>,
    #[serde(default)]
    reputation: Option<WireGroupConfig>,
}

impl From<WireGroups> for core::Groups {
    fn from(w: WireGroups) -> Self {
        core::Groups {
            injection: w.injection.map(Into::into),
            signatures: w.signatures.map(Into::into),
            structural: w.structural.map(Into::into),
            reputation: w.reputation.map(Into::into),
        }
    }
}

/// camelCase + lenient-int wrapper for `core::XffConfig`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireXff {
    #[serde(default, deserialize_with = "de_lenient_usize")]
    trusted_hops: usize,
}

impl Default for WireXff {
    fn default() -> Self {
        WireXff { trusted_hops: 0 }
    }
}

impl From<WireXff> for core::XffConfig {
    fn from(w: WireXff) -> Self {
        core::XffConfig {
            trusted_hops: w.trusted_hops,
        }
    }
}

/// camelCase + lenient-int wrapper for `core::ReputationConfig`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireReputation {
    #[serde(default = "default_per_second", deserialize_with = "de_lenient_u32")]
    per_second: u32,
    #[serde(default)]
    deny_list: Vec<String>,
    /// Cap on the per-IP rate-limit map (NEW-H2). Defaults to 50,000;
    /// raising it lets a tenant absorb more legitimate cardinality at
    /// the cost of more memory under adversarial IP rotation.
    #[serde(
        default = "default_max_tracked_ips",
        deserialize_with = "de_lenient_usize"
    )]
    max_tracked_ips: usize,
}

fn default_per_second() -> u32 {
    100
}

fn default_max_tracked_ips() -> usize {
    50_000
}

impl Default for WireReputation {
    fn default() -> Self {
        WireReputation {
            per_second: default_per_second(),
            deny_list: Vec::new(),
            max_tracked_ips: default_max_tracked_ips(),
        }
    }
}

impl From<WireReputation> for core::ReputationConfig {
    fn from(w: WireReputation) -> Self {
        core::ReputationConfig {
            per_second: w.per_second,
            deny_list: w.deny_list,
            max_tracked_ips: w.max_tracked_ips,
        }
    }
}

/// camelCase + lenient-int wrapper for `core::BodyConfig`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireBody {
    #[serde(
        default = "default_max_inspect_bytes",
        deserialize_with = "de_lenient_usize"
    )]
    max_inspect_bytes: usize,
    #[serde(default = "default_over_cap")]
    over_cap: core::OverCap,
}

fn default_max_inspect_bytes() -> usize {
    1_048_576
}
fn default_over_cap() -> core::OverCap {
    core::OverCap::Pass
}

impl Default for WireBody {
    fn default() -> Self {
        WireBody {
            max_inspect_bytes: default_max_inspect_bytes(),
            over_cap: default_over_cap(),
        }
    }
}

/// Top-level wire shape Traefik delivers.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Wire {
    mode: core::Mode,
    #[serde(default = "default_fail_mode")]
    fail_mode: WireFailMode,
    #[serde(default)]
    body: WireBody,
    #[serde(default)]
    groups: WireGroups,
    #[serde(default)]
    reputation: WireReputation,
    #[serde(default)]
    xff: WireXff,
}

fn default_fail_mode() -> WireFailMode {
    WireFailMode::FailOpen
}

fn default_group(enabled: bool, mode: core::GroupMode) -> core::GroupConfig {
    core::GroupConfig { enabled, mode }
}

/// Parse the raw JSON bytes Traefik hands the plugin.
pub fn parse(bytes: &[u8]) -> Result<core::Config, String> {
    let w: Wire = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    // NEW-M7: range validation. Pre-fix the adapter silently coerced
    // `perSecond: 0` to 1 rps (most restrictive — looked like "disable"
    // but was actually "rate-limit to 1 req/s") and `maxInspectBytes: 0`
    // silently disabled body inspection while overCap still applied. Both
    // are almost always tenant typos, so we surface them at parse time.
    if w.reputation.per_second == 0 {
        return Err(
            "reputation.perSecond must be > 0; use groups.reputation.enabled=false to disable"
                .to_string(),
        );
    }
    if w.body.max_inspect_bytes == 0 {
        return Err(
            "body.maxInspectBytes must be > 0; remove the field to use the default 1 MiB"
                .to_string(),
        );
    }
    let mut cfg = core::Config {
        mode: w.mode,
        fail_mode: w.fail_mode.into(),
        body: core::BodyConfig {
            max_inspect_bytes: w.body.max_inspect_bytes,
            over_cap: w.body.over_cap,
        },
        groups: w.groups.into(),
        reputation: w.reputation.into(),
        xff: w.xff.into(),
    };
    cfg.groups
        .injection
        .get_or_insert(default_group(true, core::GroupMode::Enforce));
    cfg.groups
        .signatures
        .get_or_insert(default_group(true, core::GroupMode::Enforce));
    cfg.groups
        .structural
        .get_or_insert(default_group(true, core::GroupMode::Monitor));
    cfg.groups
        .reputation
        .get_or_insert(default_group(false, core::GroupMode::Monitor));
    Ok(cfg)
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

    #[test]
    fn missing_groups_get_documented_defaults() {
        let json = br#"{ "mode": "enforce" }"#;
        let cfg = parse(json).expect("parse");

        let inj = cfg
            .groups
            .injection
            .as_ref()
            .expect("injection default applied");
        assert!(inj.enabled);
        assert_eq!(inj.mode, core::GroupMode::Enforce);

        let sig = cfg
            .groups
            .signatures
            .as_ref()
            .expect("signatures default applied");
        assert!(sig.enabled);
        assert_eq!(sig.mode, core::GroupMode::Enforce);

        let str_ = cfg
            .groups
            .structural
            .as_ref()
            .expect("structural default applied");
        assert!(str_.enabled);
        assert_eq!(str_.mode, core::GroupMode::Monitor);

        let rep = cfg
            .groups
            .reputation
            .as_ref()
            .expect("reputation default applied");
        assert!(!rep.enabled); // reputation is documented OFF by default
        assert_eq!(rep.mode, core::GroupMode::Monitor);
    }

    #[test]
    fn explicit_group_overrides_default() {
        let json = br#"{
          "mode": "enforce",
          "groups": { "structural": { "enabled": false, "mode": "monitor" } }
        }"#;
        let cfg = parse(json).expect("parse");
        let str_ = cfg.groups.structural.as_ref().expect("structural present");
        assert!(!str_.enabled);
    }

    /// Tenant config typos must surface at parse time. Pre-I-2 the adapter
    /// silently ignored unknown fields, so a Middleware written as
    /// `groupz:` (instead of `groups:`) would parse fine and the WAF would
    /// run with built-in defaults — a tenant footgun. After the fix the
    /// adapter rejects unknown fields at every nesting level.
    #[test]
    fn rejects_unknown_top_level_field() {
        let json = br#"{ "mode": "monitor", "groupz": { } }"#;
        let err = parse(json).expect_err("unknown top-level field must error");
        assert!(
            err.contains("groupz"),
            "error should mention the bad key: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field_inside_groups() {
        let json = br#"{
          "mode": "monitor",
          "groups": { "injction": { "enabled": true } }
        }"#;
        let err = parse(json).expect_err("unknown nested field must error");
        assert!(
            err.contains("injction"),
            "error should mention the bad key: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field_inside_group_config() {
        let json = br#"{
          "mode": "monitor",
          "groups": { "injection": { "enabld": true } }
        }"#;
        let err = parse(json).expect_err("unknown field inside group must error");
        assert!(
            err.contains("enabld"),
            "error should mention the bad key: {err}"
        );
    }

    // NEW-M5: typo coverage for body + reputation wire types.
    #[test]
    fn rejects_unknown_field_inside_body() {
        let json = br#"{
          "mode": "monitor",
          "body": { "maxinspctbytes": 1024 }
        }"#;
        let err = parse(json).expect_err("unknown field inside body must error");
        assert!(
            err.contains("maxinspctbytes"),
            "error should mention the bad key: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field_inside_reputation() {
        let json = br#"{
          "mode": "monitor",
          "reputation": { "perSeocnd": 50 }
        }"#;
        let err = parse(json).expect_err("unknown field inside reputation must error");
        assert!(
            err.contains("perSeocnd"),
            "error should mention the bad key: {err}"
        );
    }

    // NEW-M6: empty-string bool is a typo, not a directive.
    #[test]
    fn rejects_empty_string_for_enabled_bool() {
        let json = br#"{
          "mode": "monitor",
          "groups": { "injection": { "enabled": "" } }
        }"#;
        let err = parse(json).expect_err("empty boolean string must error");
        assert!(
            err.contains("invalid boolean string"),
            "error should call out the bad value: {err}"
        );
    }

    // NEW-M7: zero ranges are surfaced rather than silently coerced.
    #[test]
    fn rejects_per_second_zero() {
        let json = br#"{
          "mode": "enforce",
          "reputation": { "perSecond": 0 }
        }"#;
        let err = parse(json).expect_err("perSecond=0 must error");
        assert!(err.contains("perSecond"), "error: {err}");
    }

    #[test]
    fn rejects_max_inspect_bytes_zero() {
        let json = br#"{
          "mode": "enforce",
          "body": { "maxInspectBytes": 0, "overCap": "pass" }
        }"#;
        let err = parse(json).expect_err("maxInspectBytes=0 must error");
        assert!(err.contains("maxInspectBytes"), "error: {err}");
    }

    /// Traefik serializes YAML booleans/integers to JSON STRINGS when
    /// forwarding plugin config to a WASM guest. The adapter must accept
    /// the stringified form or every Middleware fails at startup.
    #[test]
    fn accepts_traefik_stringified_primitives() {
        let json = br#"{
          "mode": "enforce",
          "failMode": "failOpen",
          "body": { "maxInspectBytes": "2048", "overCap": "pass" },
          "groups": {
            "injection":  { "enabled": "true",  "mode": "enforce" },
            "signatures": { "enabled": "false", "mode": "monitor" }
          },
          "reputation": { "perSecond": "250", "denyList": ["9.9.9.9"] }
        }"#;
        let cfg = parse(json).expect("parse stringified primitives");
        assert_eq!(cfg.body.max_inspect_bytes, 2048);
        assert!(cfg.groups.injection.as_ref().unwrap().enabled);
        assert!(!cfg.groups.signatures.as_ref().unwrap().enabled);
        assert_eq!(cfg.reputation.per_second, 250);
        assert_eq!(cfg.reputation.deny_list, vec!["9.9.9.9".to_string()]);
    }
}
