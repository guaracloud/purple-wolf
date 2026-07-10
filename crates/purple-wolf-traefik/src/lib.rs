//! purple-wolf-traefik: http-wasm guest plugin wrapping `purple-wolf-core`.
//!
//! Traefik compiles the module through a shared wazero cache. Each configured
//! `Middleware` owns an http-wasm host middleware whose guest pool may contain
//! multiple independent WASM instances under concurrency.

// Panic-surface discipline (see purple-wolf-core/src/lib.rs for the full
// rationale): unwinding is unavailable on `wasm32-wasip1`, so a panic in the
// guest traps the instance and bypasses `failMode`. Deny the panic-producing
// patterns in production paths; test modules opt out.
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::expect_used)]

// `config` is `pub` so the native `purple-wolf-validate` binary can reuse the
// exact same Traefik-config adapter operators' Middlewares are parsed with —
// no second, drifting parser. It carries no wasm-only state.
pub mod config;
mod entry;
mod host;

// Re-export the exported functions so they appear in the .wasm export table.
pub use entry::{handle_request, handle_response};

/// Validate a Traefik plugin config payload (the JSON Traefik passes to the
/// guest) without running the WAF. Returns `Ok(warnings)` when the config
/// parses — warnings are non-fatal advisories (e.g. dropped reserved label
/// keys) — or `Err(message)` when it would fail to load. The
/// `purple-wolf-validate` binary and operator CI use this for parity with
/// the relay's `--validate-only`.
pub fn validate_config(bytes: &[u8]) -> Result<Vec<String>, String> {
    config::parse(bytes).map(|(_cfg, warnings)| warnings)
}

#[cfg(test)]
mod validate_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::validate_config;

    #[test]
    fn accepts_a_valid_minimal_config() {
        // Traefik stringifies scalars; a minimal valid config parses Ok.
        let json = br#"{"mode":"enforce","failMode":"failOpen"}"#;
        let res = validate_config(json);
        assert!(res.is_ok(), "valid config must validate: {res:?}");
    }

    #[test]
    fn rejects_an_unknown_key() {
        // deny_unknown_fields: a typo'd key must be a hard validation error,
        // since in production it silently demotes the middleware to monitor.
        let json = br#"{"mode":"enforce","failMode":"failOpen","modee":"enforce"}"#;
        let res = validate_config(json);
        assert!(res.is_err(), "unknown key must fail validation: {res:?}");
    }

    #[test]
    fn rejects_malformed_json() {
        let res = validate_config(b"{not json");
        assert!(res.is_err(), "malformed JSON must fail validation");
    }
}
