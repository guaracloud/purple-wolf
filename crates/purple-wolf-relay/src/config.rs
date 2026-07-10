//! Relay configuration schema, loader, and validator.
//!
//! The on-disk format is YAML (the canonical form documented in
//! examples/) or JSON (same schema, recognized by `.json` extension).
//! `deny_unknown_fields` is set at every level so a typo in a tenant
//! config fails loudly rather than silently disabling a subscriber.
//!
//! `validate()` resolves secret references (env var lookups, file
//! reads) into a `Resolved` struct so the raw `Config` stays loggable
//! without leaking secrets via debug output.

use serde::Deserialize;
use std::collections::BTreeMap;

// ---------- top-level ----------

/// Top-level relay configuration. Loaded from YAML or JSON.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// One or more event sources. Required (validator rejects empty).
    pub sources: Vec<SourceConfig>,
    /// Zero or more enrichers, applied in order to each envelope.
    #[serde(default)]
    pub enrichments: Vec<EnricherConfig>,
    /// Zero or more webhook subscribers.
    pub subscribers: Vec<SubscriberConfig>,
    /// Process-wide knobs (mostly defaultable).
    #[serde(default)]
    pub relay: RelayConfig,
}

/// Process-wide knobs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Identifier for THIS relay instance; appears in the envelope's
    /// `source.relay_instance`. Defaults to the OS hostname so cluster-wide
    /// dedup works out of the box when running ≥1 relay.
    #[serde(default)]
    pub instance_id: Option<String>,
    /// Max in-flight deliveries per subscriber (mpsc bound). A full queue
    /// drops events for THAT subscriber, never backpressures the fan-out.
    #[serde(default = "default_subscriber_queue")]
    pub subscriber_queue: usize,
    /// Optional bearer-token guard for the admin data/metadata surface
    /// (/metrics, /version). Probe endpoints (/healthz, /readyz) stay open.
    /// When unset the admin surface is open — the original default — and the relay logs a
    /// startup warning. The token is referenced indirectly so it never sits
    /// in the config file: exactly one of `admin_token_env` / `admin_token_file`.
    #[serde(default)]
    pub admin_token_env: Option<String>,
    #[serde(default)]
    pub admin_token_file: Option<std::path::PathBuf>,
}
impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            instance_id: None,
            subscriber_queue: default_subscriber_queue(),
            admin_token_env: None,
            admin_token_file: None,
        }
    }
}
fn default_subscriber_queue() -> usize {
    10_000
}

// ---------- sources ----------

/// Tagged union of source kinds. Extending it with Kafka, Loki, Vector, or
/// other sources is purely additive.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceConfig {
    /// Tail a file (e.g., Traefik's access log). Survives rotation.
    LogTail {
        path: std::path::PathBuf,
        /// If true, read from offset 0 on first start; otherwise seek
        /// to end. Bookmarks across restarts are independent of this.
        #[serde(default)]
        from_beginning: bool,
    },
    /// Read line-buffered from stdin until EOF.
    Stdin,
}

// ---------- enrichers ----------

/// Tagged union of enricher kinds. Each enricher runs per-envelope with
/// a per-call timeout; failure is non-fatal (degraded service, not
/// pipeline failure).
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnricherConfig {
    /// Static lookup: for an envelope with `labels[on_label] == K`,
    /// merge `table[K]` into the labels (new keys only — never overwrites).
    Lookup {
        on_label: String,
        table: BTreeMap<String, BTreeMap<String, String>>,
    },
    /// HTTP enricher: GET `url` (with `{value}` substituted for the
    /// label value), parse the JSON body as `BTreeMap<String,String>`,
    /// merge into labels. Cached per label value for `cache_ttl_s`, bounded
    /// by `cache_capacity`.
    Http {
        on_label: String,
        url: String,
        #[serde(default = "default_enricher_timeout_ms")]
        timeout_ms: u64,
        #[serde(default = "default_cache_ttl_s")]
        cache_ttl_s: u64,
        #[serde(default = "default_cache_capacity")]
        cache_capacity: usize,
    },
}
fn default_enricher_timeout_ms() -> u64 {
    500
}
fn default_cache_ttl_s() -> u64 {
    300
}
fn default_cache_capacity() -> usize {
    1024
}

// ---------- subscribers ----------

/// One subscriber definition. The `id` is operator-controlled and
/// surfaces in metrics labels — keep it bounded-cardinality (per
/// deployment) for sane Prometheus storage.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriberConfig {
    pub id: String,
    pub url: String,
    /// Name of the env var holding the HMAC secret. One of `secret_env`
    /// / `secret_file` must be set; both being set is a parse error.
    #[serde(default)]
    pub secret_env: Option<String>,
    /// Path to a file whose contents are the HMAC secret.
    #[serde(default)]
    pub secret_file: Option<std::path::PathBuf>,
    /// Optional filter; defaults to "match everything".
    #[serde(default)]
    pub filter: SubscriberFilter,
    /// Retry policy. Defaults documented in `RetryConfig::default`.
    #[serde(default)]
    pub retry: RetryConfig,
    /// Per-delivery HTTP timeout (relay considers a slow subscriber as
    /// a retryable failure once this elapses).
    #[serde(default = "default_subscriber_timeout_ms")]
    pub timeout_ms: u64,
    /// Toggle without deleting. Defaults to true.
    #[serde(default = "default_true")]
    pub enabled: bool,
}
fn default_true() -> bool {
    true
}
fn default_subscriber_timeout_ms() -> u64 {
    30_000
}

/// Filter expression evaluated against each `Envelope`. Compiled into a
/// fast predicate in the subscriber-filter module (Phase F Task 16).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriberFilter {
    /// All `(k, v)` pairs in this map must match the envelope's labels
    /// exactly (envelope must be a superset).
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Minimum severity (envelope's `blocked_severity` OR the max
    /// `would_block_rules` severity must be ≥ this).
    #[serde(default)]
    pub severity_min: Option<Severity>,
    /// Glob match against `event.blocked_rule` (and falls back to
    /// matching any `would_block_rules` entry for allow-mode events).
    /// `*` is the only wildcard.
    #[serde(default)]
    pub blocked_rule_pattern: Option<String>,
}

/// Audit-line severity, ordered so the derived `Ord` does the right
/// thing in `severity_min` comparisons.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Retry policy. Backoff is exponential with ±20% jitter (see Phase F).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_base_delay_ms")]
    pub base_delay_ms: u64,
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,
}
fn default_max_attempts() -> u32 {
    8
}
fn default_base_delay_ms() -> u64 {
    500
}
fn default_max_delay_ms() -> u64 {
    600_000
}
impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            base_delay_ms: default_base_delay_ms(),
            max_delay_ms: default_max_delay_ms(),
        }
    }
}

// ---------- loader ----------

/// Load YAML or JSON from disk, picking the parser by extension.
pub fn load_from_file(path: &std::path::Path) -> anyhow::Result<Config> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading config {}: {e}", path.display()))?;
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    load_from_str_with_ext(&text, ext).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
}

/// Test-friendly entrypoint: parse a YAML/JSON string.
pub fn load_from_str(text: &str) -> anyhow::Result<Config> {
    load_from_str_with_ext(text, "yaml")
}

fn load_from_str_with_ext(text: &str, ext: &str) -> anyhow::Result<Config> {
    let cfg: Config = match ext {
        "json" => {
            serde_json::from_str(text).map_err(|e| anyhow::anyhow!("parsing JSON config: {e}"))?
        }
        // YAML is a superset of JSON, so this also covers .yml and the
        // common case of operators using either.
        _ => serde_yaml::from_str(text).map_err(|e| anyhow::anyhow!("parsing YAML config: {e}"))?,
    };
    Ok(cfg)
}

// ---------- validator ----------

/// Validated config + resolved secrets. Held separately so the raw
/// `Config` stays loggable without ever exposing secret material.
#[derive(Debug)]
pub struct Resolved {
    pub raw: Config,
    /// `subscriber.id` → resolved HMAC secret bytes.
    pub subscriber_secrets: BTreeMap<String, zeroize::Zeroizing<Vec<u8>>>,
    /// Stable identifier for THIS relay instance (resolved from
    /// `relay.instance_id` or the OS hostname).
    pub instance_id: String,
    /// Resolved admin bearer token, or `None` when the admin surface is open.
    pub admin_token: Option<zeroize::Zeroizing<String>>,
}

/// Resolve the optional admin bearer token from its env/file reference.
/// Mirrors the subscriber-secret rules: at most one of the two references,
/// non-empty when present. `None` means the admin surface is left open.
fn resolve_admin_token(relay: &RelayConfig) -> anyhow::Result<Option<zeroize::Zeroizing<String>>> {
    match (&relay.admin_token_env, &relay.admin_token_file) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => {
            anyhow::bail!("relay: only one of admin_token_env / admin_token_file may be set")
        }
        (Some(env_name), None) => {
            let v = std::env::var(env_name)
                .map_err(|_| anyhow::anyhow!("relay: admin_token_env {env_name:?} is not set"))?;
            if v.is_empty() {
                anyhow::bail!("relay: admin_token_env {env_name:?} is empty");
            }
            Ok(Some(zeroize::Zeroizing::new(v)))
        }
        (None, Some(path)) => {
            let s = std::fs::read_to_string(path).map_err(|e| {
                anyhow::anyhow!("relay: reading admin_token_file {}: {e}", path.display())
            })?;
            let trimmed = s.trim().to_string();
            if trimmed.is_empty() {
                anyhow::bail!("relay: admin_token_file {} is empty", path.display());
            }
            Ok(Some(zeroize::Zeroizing::new(trimmed)))
        }
    }
}

/// Validate cross-field invariants and resolve secret references.
pub fn validate(cfg: &Config) -> anyhow::Result<Resolved> {
    if cfg.sources.is_empty() {
        anyhow::bail!("config: at least one source must be configured");
    }
    if cfg.relay.subscriber_queue == 0 {
        anyhow::bail!("relay.subscriber_queue must be greater than zero");
    }
    if cfg.subscribers.is_empty() {
        tracing::warn!("config: no subscribers configured; relay will start but deliver nothing");
    }

    // Subscriber ids must be unique — they appear in metrics labels and
    // an admin endpoint addresses subscribers by id.
    let mut seen_ids: BTreeMap<&str, ()> = BTreeMap::new();
    for s in &cfg.subscribers {
        if seen_ids.insert(s.id.as_str(), ()).is_some() {
            anyhow::bail!("config: duplicate subscriber id {:?}", s.id);
        }
    }

    let mut subscriber_secrets: BTreeMap<String, zeroize::Zeroizing<Vec<u8>>> = BTreeMap::new();
    for s in &cfg.subscribers {
        // URL must parse and use http(s).
        let scheme_ok = s.url.starts_with("http://") || s.url.starts_with("https://");
        if !scheme_ok {
            anyhow::bail!(
                "subscriber {:?}: url {:?} must be http:// or https://",
                s.id,
                s.url
            );
        }

        // Exactly one of secret_env / secret_file.
        let secret = match (&s.secret_env, &s.secret_file) {
            (Some(_), Some(_)) => anyhow::bail!(
                "subscriber {:?}: only one of secret_env / secret_file may be set",
                s.id
            ),
            (None, None) => anyhow::bail!(
                "subscriber {:?}: one of secret_env / secret_file must be set",
                s.id
            ),
            (Some(env_name), None) => {
                let v = std::env::var(env_name).map_err(|_| {
                    anyhow::anyhow!(
                        "subscriber {:?}: env var {:?} (referenced by secret_env) is not set",
                        s.id,
                        env_name
                    )
                })?;
                if v.is_empty() {
                    anyhow::bail!(
                        "subscriber {:?}: env var {:?} (referenced by secret_env) is empty",
                        s.id,
                        env_name
                    );
                }
                v.into_bytes()
            }
            (None, Some(path)) => {
                let bytes = std::fs::read(path).map_err(|e| {
                    anyhow::anyhow!(
                        "subscriber {:?}: reading secret_file {}: {e}",
                        s.id,
                        path.display()
                    )
                })?;
                let trimmed: Vec<u8> = bytes
                    .into_iter()
                    .rev()
                    .skip_while(|b| matches!(*b, b'\n' | b'\r' | b' ' | b'\t'))
                    .collect::<Vec<u8>>()
                    .into_iter()
                    .rev()
                    .collect();
                if trimmed.is_empty() {
                    anyhow::bail!(
                        "subscriber {:?}: secret_file {} is empty",
                        s.id,
                        path.display()
                    );
                }
                trimmed
            }
        };
        subscriber_secrets.insert(s.id.clone(), zeroize::Zeroizing::new(secret));

        // Retry: max_attempts must be ≥ 1 and base ≤ max.
        if s.retry.max_attempts == 0 {
            anyhow::bail!("subscriber {:?}: retry.max_attempts must be ≥ 1", s.id);
        }
        if s.retry.base_delay_ms > s.retry.max_delay_ms {
            anyhow::bail!(
                "subscriber {:?}: retry.base_delay_ms ({}) > retry.max_delay_ms ({})",
                s.id,
                s.retry.base_delay_ms,
                s.retry.max_delay_ms
            );
        }
    }

    let any_enabled = cfg.subscribers.iter().any(|s| s.enabled);
    if !any_enabled {
        tracing::warn!(
            "config: every subscriber is disabled; relay will start but deliver nothing"
        );
    }

    let instance_id = cfg
        .relay
        .instance_id
        .clone()
        .or_else(|| {
            gethostname::gethostname()
                .into_string()
                .ok()
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "purple-wolf-relay".to_string());

    let admin_token = resolve_admin_token(&cfg.relay)?;

    Ok(Resolved {
        raw: cfg.clone(),
        subscriber_secrets,
        instance_id,
        admin_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_minimal_yaml() {
        let cfg = load_from_str(
            r#"
            sources: [{ type: stdin }]
            subscribers:
              - id: a
                url: https://x/y
                secret_env: TEST_SECRET_LOADS_MINIMAL
            "#,
        )
        .unwrap();
        assert_eq!(cfg.sources.len(), 1);
        assert_eq!(cfg.subscribers.len(), 1);
        assert!(matches!(cfg.sources[0], SourceConfig::Stdin));
    }

    #[test]
    fn loads_json_when_extension_is_json() {
        let cfg = load_from_str_with_ext(
            r#"{
                "sources":[{"type":"stdin"}],
                "subscribers":[{"id":"a","url":"https://x/y","secret_env":"S"}]
            }"#,
            "json",
        )
        .unwrap();
        assert_eq!(cfg.sources.len(), 1);
        assert_eq!(cfg.subscribers.len(), 1);
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let err = load_from_str("sources: []\nsubscribers: []\nbogus: true").unwrap_err();
        assert!(err.to_string().contains("bogus"), "err: {err}");
    }

    #[test]
    fn admin_token_defaults_to_none_open() {
        let relay = RelayConfig::default();
        assert!(resolve_admin_token(&relay).unwrap().is_none());
    }

    #[test]
    fn admin_token_resolves_from_env() {
        std::env::set_var("TEST_ADMIN_TOKEN_RESOLVES", "tok-123");
        let relay = RelayConfig {
            admin_token_env: Some("TEST_ADMIN_TOKEN_RESOLVES".into()),
            ..RelayConfig::default()
        };
        let resolved = resolve_admin_token(&relay).unwrap();
        assert_eq!(resolved.as_deref().map(String::as_str), Some("tok-123"));
        std::env::remove_var("TEST_ADMIN_TOKEN_RESOLVES");
    }

    #[test]
    fn admin_token_rejects_both_references() {
        let relay = RelayConfig {
            admin_token_env: Some("X".into()),
            admin_token_file: Some("/tmp/x".into()),
            ..RelayConfig::default()
        };
        let err = resolve_admin_token(&relay).unwrap_err();
        assert!(err.to_string().contains("only one of"), "err: {err}");
    }

    #[test]
    fn admin_token_rejects_missing_env() {
        let relay = RelayConfig {
            admin_token_env: Some("TEST_ADMIN_TOKEN_DEFINITELY_UNSET_XYZ".into()),
            ..RelayConfig::default()
        };
        let err = resolve_admin_token(&relay).unwrap_err();
        assert!(err.to_string().contains("is not set"), "err: {err}");
    }

    #[test]
    fn rejects_unknown_subscriber_field() {
        let err = load_from_str(
            r#"
            sources: [{ type: stdin }]
            subscribers:
              - { id: a, url: https://x/y, secret_env: S, weird: 1 }
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("weird"), "err: {err}");
    }

    #[test]
    fn rejects_unknown_source_type() {
        let err = load_from_str(
            r#"
            sources: [{ type: kafka, topic: x }]
            subscribers: [{ id: a, url: https://x/y, secret_env: S }]
            "#,
        )
        .unwrap_err();
        // serde_yaml's tagged-union error mentions the bad variant name.
        assert!(err.to_string().contains("kafka"), "err: {err}");
    }

    #[test]
    fn http_enricher_defaults_include_bounded_cache_capacity() {
        let cfg = load_from_str(
            r#"
            sources: [{ type: stdin }]
            enrichments:
              - type: http
                on_label: tenant
                url: https://catalog.example/tenants/{value}
            subscribers: []
            "#,
        )
        .unwrap();
        match &cfg.enrichments[0] {
            EnricherConfig::Http {
                cache_ttl_s,
                cache_capacity,
                ..
            } => {
                assert_eq!(*cache_ttl_s, 300);
                assert_eq!(*cache_capacity, 1024);
            }
            other => panic!("expected http enricher, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_no_sources() {
        let cfg = load_from_str(
            r#"
            sources: []
            subscribers: [{ id: a, url: https://x/y, secret_env: S }]
            "#,
        )
        .unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("source"), "err: {err}");
    }

    #[test]
    fn validate_accepts_no_subscribers() {
        let cfg = load_from_str(
            r#"
            sources: [{ type: stdin }]
            subscribers: []
            "#,
        )
        .unwrap();
        let resolved = validate(&cfg).unwrap();
        assert!(resolved.subscriber_secrets.is_empty());
    }

    #[test]
    fn validate_rejects_zero_subscriber_queue_before_runtime_channel_creation() {
        let cfg = load_from_str(
            r#"
            sources: [{ type: stdin }]
            subscribers: []
            relay: { subscriber_queue: 0 }
            "#,
        )
        .unwrap();
        let error = validate(&cfg).unwrap_err();
        assert!(
            error.to_string().contains("subscriber_queue"),
            "err: {error}"
        );
    }

    #[test]
    fn validate_rejects_subscriber_missing_secret() {
        let cfg = load_from_str(
            r#"
            sources: [{ type: stdin }]
            subscribers:
              - { id: a, url: https://x/y }
            "#,
        )
        .unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("secret_env"), "err: {err}");
    }

    #[test]
    fn validate_rejects_subscriber_with_both_secret_kinds() {
        let cfg = load_from_str(
            r#"
            sources: [{ type: stdin }]
            subscribers:
              - { id: a, url: https://x/y, secret_env: S, secret_file: /tmp/x }
            "#,
        )
        .unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("only one"), "err: {err}");
    }

    #[test]
    fn validate_rejects_subscriber_bad_url_scheme() {
        let cfg = load_from_str(
            r#"
            sources: [{ type: stdin }]
            subscribers:
              - { id: a, url: ftp://x/y, secret_env: S }
            "#,
        )
        .unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("http"), "err: {err}");
    }

    #[test]
    fn validate_rejects_duplicate_subscriber_ids() {
        let cfg = load_from_str(
            r#"
            sources: [{ type: stdin }]
            subscribers:
              - { id: a, url: https://x/y, secret_env: S1 }
              - { id: a, url: https://z/w, secret_env: S2 }
            "#,
        )
        .unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("duplicate"), "err: {err}");
    }

    #[test]
    fn validate_resolves_secret_env() {
        // Use a unique env-var name so parallel test runs don't collide.
        let name = "TEST_RESOLVES_SECRET_ENV_PWREL";
        std::env::set_var(name, "supersecret");
        let cfg = load_from_str(&format!(
            r#"
            sources: [{{ type: stdin }}]
            subscribers:
              - {{ id: a, url: https://x/y, secret_env: {name} }}
            "#,
        ))
        .unwrap();
        let resolved = validate(&cfg).unwrap();
        let bytes = resolved.subscriber_secrets.get("a").unwrap();
        assert_eq!(bytes.as_slice(), b"supersecret");
        std::env::remove_var(name);
    }

    #[test]
    fn validate_resolves_secret_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"file-secret\n").unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        let cfg = load_from_str(&format!(
            r#"
            sources: [{{ type: stdin }}]
            subscribers:
              - {{ id: a, url: https://x/y, secret_file: {path} }}
            "#,
        ))
        .unwrap();
        let resolved = validate(&cfg).unwrap();
        // Trailing newline is trimmed by the loader (avoids the
        // "editor saved \n at end of file" footgun).
        assert_eq!(
            resolved.subscriber_secrets.get("a").unwrap().as_slice(),
            b"file-secret"
        );
    }

    #[test]
    fn validate_rejects_empty_secret_env() {
        let name = "TEST_EMPTY_SECRET_ENV_PWREL";
        std::env::set_var(name, "");
        let cfg = load_from_str(&format!(
            r#"
            sources: [{{ type: stdin }}]
            subscribers:
              - {{ id: a, url: https://x/y, secret_env: {name} }}
            "#,
        ))
        .unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("empty"), "err: {err}");
        std::env::remove_var(name);
    }

    #[test]
    fn validate_rejects_zero_max_attempts() {
        let name = "TEST_ZERO_MAX_ATTEMPTS_PWREL";
        std::env::set_var(name, "x");
        let cfg = load_from_str(&format!(
            r#"
            sources: [{{ type: stdin }}]
            subscribers:
              - id: a
                url: https://x/y
                secret_env: {name}
                retry: {{ max_attempts: 0 }}
            "#,
        ))
        .unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("max_attempts"), "err: {err}");
        std::env::remove_var(name);
    }

    #[test]
    fn validate_rejects_base_delay_over_max_delay() {
        let name = "TEST_BASE_OVER_MAX_PWREL";
        std::env::set_var(name, "x");
        let cfg = load_from_str(&format!(
            r#"
            sources: [{{ type: stdin }}]
            subscribers:
              - id: a
                url: https://x/y
                secret_env: {name}
                retry: {{ base_delay_ms: 10000, max_delay_ms: 1000 }}
            "#,
        ))
        .unwrap();
        let err = validate(&cfg).unwrap_err();
        assert!(err.to_string().contains("base_delay_ms"), "err: {err}");
        std::env::remove_var(name);
    }

    #[test]
    fn validate_fills_instance_id_when_omitted() {
        let name = "TEST_INSTANCE_ID_DEFAULT_PWREL";
        std::env::set_var(name, "x");
        let cfg = load_from_str(&format!(
            r#"
            sources: [{{ type: stdin }}]
            subscribers:
              - {{ id: a, url: https://x/y, secret_env: {name} }}
            "#,
        ))
        .unwrap();
        let resolved = validate(&cfg).unwrap();
        assert!(!resolved.instance_id.is_empty());
        std::env::remove_var(name);
    }

    #[test]
    fn severity_orders_low_to_critical() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn subscriber_filter_defaults_to_empty() {
        let f = SubscriberFilter::default();
        assert!(f.labels.is_empty());
        assert!(f.severity_min.is_none());
        assert!(f.blocked_rule_pattern.is_none());
    }
}
