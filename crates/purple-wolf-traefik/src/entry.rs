//! The http-wasm guest entry: parse config, build a [`Request`], run the
//! [`Engine`], apply policy, either pass through or short-circuit with 403,
//! and emit an audit line via the host log sink.

use crate::{config as adapter, host};
use purple_wolf_core::{
    audit::{self, AuditEntry},
    config::{BodyConfig, Config, FailMode, Mode, OverCap, ReputationConfig},
    detectors::{
        injection::InjectionDetector, reputation::ReputationDetector,
        signatures::SignatureDetector, structural::StructuralDetector, Engine, Group,
    },
    policy::{self, Action},
    request::{self, Request},
};
use std::cell::OnceCell;
use std::net::IpAddr;

/// Build the engine for one plugin instance, given its config.
fn engine(cfg: &Config) -> Engine {
    let ips: Vec<IpAddr> = cfg
        .reputation
        .deny_list
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    Engine::new(vec![
        Box::new(InjectionDetector),
        Box::new(SignatureDetector::new()),
        Box::new(StructuralDetector),
        Box::new(ReputationDetector::with_capacity(
            cfg.reputation.per_second,
            ips,
            cfg.reputation.max_tracked_ips,
        )),
    ])
}

thread_local! {
    // (config, engine, on_fallback_config). `on_fallback_config` is true when
    // the operator's Middleware config failed to parse and we built the
    // all-monitor fallback — surfaced on every audit line so dashboards see
    // that enforcement is silently off, not just at the one startup log.
    static STATE: OnceCell<(Config, Engine, bool)> = const { OnceCell::new() };
}

fn state<R>(f: impl FnOnce(&Config, &Engine, bool) -> R) -> R {
    STATE.with(|s| {
        let (cfg, engine_, fallback) = s.get_or_init(|| {
            let (cfg, fallback) = match adapter::parse(&host::config()) {
                Ok((cfg, warnings)) => {
                    for w in &warnings {
                        host::log(&format!("purple-wolf: {w}"));
                    }
                    (cfg, false)
                }
                Err(e) => {
                    host::log(&format!(
                        "purple-wolf: invalid Middleware config ({e}); falling back to global monitor mode — every detector enabled in monitor; verdicts will appear in audit logs but the WAF will not block. Reload Traefik with a valid config to enable enforcement."
                    ));
                    // Build a deliberately-noisy fallback: every group runs in
                    // monitor, so the operator can see verdicts in audit logs and
                    // diagnose. Previously this constructed `groups: Default()`
                    // which silently disabled every detector — making a bad
                    // config a silent no-op WAF.
                    let cfg = Config {
                        mode: Mode::Monitor,
                        fail_mode: FailMode::FailOpen,
                        body: BodyConfig {
                            max_inspect_bytes: 1_048_576,
                            over_cap: OverCap::Pass,
                        },
                        groups: purple_wolf_core::config::Groups::all_monitor(),
                        reputation: ReputationConfig::default(),
                        xff: purple_wolf_core::config::XffConfig::default(),
                        labels: std::collections::BTreeMap::new(),
                    };
                    (cfg, true)
                }
            };
            let eng = engine(&cfg);
            (cfg, eng, fallback)
        });
        f(cfg, engine_, *fallback)
    })
}

/// http-wasm exported entry point invoked once per request.
///
/// Returns the http-wasm "continue" signal (`1` = continue to upstream,
/// `0` = stop, response has already been written by the plugin).
#[no_mangle]
pub extern "C" fn handle_request() -> u64 {
    host::reset_response_taken();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(inspect));
    match result {
        Ok(action) => match action {
            Action::Allow => 1,
            Action::Block => 0,
        },
        Err(_) => {
            // Soft failure: detector panic. NOTE: on `wasm32-wasip1`
            // (panic = "abort") this arm is unreachable — a panic traps the
            // guest before unwinding here. It runs only on native embeddings
            // where unwinding works. See THREAT_MODEL.md §4.3 / workspace
            // Cargo.toml. Panics are excluded structurally by the crate-level
            // deny(clippy::unwrap_used/expect_used/panic) lints.
            host::log("purple-wolf: soft failure (panic) — applying fail mode");
            state(|cfg, _engine_, _fallback| match cfg.fail_mode {
                FailMode::FailOpen => 1u64,
                FailMode::FailClosed => {
                    host::write_response(403, b"inspection failed (fail_closed)");
                    0
                }
            })
        }
    }
}

fn inspect() -> Action {
    state(|cfg, engine_, fallback| {
        // Build header list (lowercased names; values are byte-faithful).
        let names = host::get_request_header_names();
        let headers: Vec<(String, String)> = names
            .iter()
            .filter_map(|n| host::get_request_header(n).map(|v| (n.to_lowercase(), v)))
            .collect();

        // Source IP: XFF → X-Real-IP → peer, gated by the configured XFF
        // trust model. Default trusted_hops=0 means "ignore XFF, use peer";
        // operators behind a trusted edge bump it to the number of trusted
        // proxies. See `purple_wolf_core::request::client_ip` for the
        // full trust-model docs.
        let peer = parse_peer(&host::get_source_addr());
        let source_ip = request::client_ip(&headers, peer, cfg.xff.trusted_hops);

        // URI split.
        let uri = host::get_uri();
        let (path, raw_query) = uri
            .split_once('?')
            .map(|(p, q)| (p.to_string(), q.to_string()))
            .unwrap_or_else(|| (uri.clone(), String::new()));
        let method = host::get_method();
        let host_hdr = headers
            .iter()
            .find(|(k, _)| k == "host")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        // Body (capped). `read_request_body` buffers at most `cap` bytes;
        // `over_cap` is true when the request carried more.
        let cap = cfg.body.max_inspect_bytes;
        let body = host::read_request_body(cap);
        let over_cap = host::request_body_exceeded(cap);
        if over_cap && cfg.body.over_cap == OverCap::Block {
            host::write_response(403, b"body exceeds inspection cap");
            return Action::Block;
        }
        // Always inspect what we buffered — including the prefix of an
        // over-cap body. Previously an over-cap body was discarded wholesale
        // (body_inspected = false), so prepending `maxInspectBytes` of padding
        // defeated body inspection for free (THREAT_MODEL §4.2). Inspecting the
        // already-buffered prefix forces an attacker to push the payload past
        // the cap rather than merely inflate the body; `body_truncated` records
        // in the audit log that bytes beyond the cap went un-inspected.
        let req = Request::build(
            &method,
            &host_hdr,
            &path,
            &raw_query,
            headers,
            body,
            true,
            source_ip,
        )
        .with_truncated_body(over_cap);

        let enabled: Vec<Group> = [
            Group::Injection,
            Group::Signatures,
            Group::Structural,
            Group::Reputation,
        ]
        .into_iter()
        .filter(|g| group_enabled(cfg, *g))
        .collect();

        let verdicts = engine_.inspect(&req, &enabled);
        let decision = policy::decide(verdicts, cfg.mode, |g| group_mode(cfg, g));

        // Audit log if anything to say. `config_fallback` makes every line
        // announce that enforcement is off when we're on the fallback config.
        let entry = AuditEntry::from_with_labels(&req, &decision, &cfg.labels)
            .with_config_fallback(fallback);
        if entry.is_noteworthy() {
            host::log(&audit::to_log_line(&entry));
        }

        match decision.action {
            Action::Allow => Action::Allow,
            Action::Block => {
                host::write_response(403, b"request blocked by purple-wolf");
                Action::Block
            }
        }
    })
}

fn group_enabled(cfg: &Config, g: Group) -> bool {
    group_mode(cfg, g) != purple_wolf_core::config::GroupMode::Off
}

fn group_mode(cfg: &Config, g: Group) -> purple_wolf_core::config::GroupMode {
    use purple_wolf_core::config::GroupMode;
    let gc = match g {
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

/// Parse the host-provided source-address string into an `IpAddr`.
///
/// The http-wasm host conventionally passes `ip:port` for IPv4 and
/// `[v6]:port` for IPv6, but neither the spec nor every wazero version
/// guarantees that — bare `ip`, `[v6]`, and missing-port forms all
/// appear in the wild. NEW-I5 in the followup review noted that the
/// previous `rsplit_once(':')` collapsed bare `::1` to the unspecified
/// IPv6 address, merging every distinct IPv6 peer to one rate-limit
/// key.
///
/// Resolution order:
///   1. Try parsing the whole string as a bare `IpAddr` (handles `::1`).
///   2. Strip a trailing `:port` (rightmost colon) and retry — covers
///      `1.2.3.4:5555` and the unbracketed-IPv6 odd case.
///   3. Strip surrounding `[...]` and retry — covers `[::1]:5555` and
///      bare `[::1]`.
///   4. Fall back to `0.0.0.0` so the request still reaches detectors;
///      the audit log will show the placeholder, signalling to the
///      operator that source-IP attribution failed for this request.
fn parse_peer(addr: &str) -> IpAddr {
    let unspecified = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
    let addr = addr.trim();
    if addr.is_empty() {
        return unspecified;
    }
    // 1. Direct parse — handles bare IPv4 and bare IPv6.
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return ip;
    }
    // 2. Strip ":port" (rightmost) and retry — handles `1.2.3.4:5555`
    //    and any unbracketed-IPv6-with-port form some hosts emit.
    if let Some((host, _)) = addr.rsplit_once(':') {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return ip;
        }
        // 3a. Strip brackets in case host = "[::1]".
        let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return ip;
        }
    }
    // 3b. Bare bracketed form `[::1]` with no port.
    let unbracketed = addr.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<IpAddr>() {
        return ip;
    }
    unspecified
}

/// http-wasm exported response hook (unused; we don't modify responses).
#[no_mangle]
pub extern "C" fn handle_response(_req_ctx: u32, _is_error: u32) {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::parse_peer;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn parses_ipv4_with_port() {
        assert_eq!(
            parse_peer("203.0.113.7:5555"),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn parses_bare_ipv4() {
        assert_eq!(
            parse_peer("203.0.113.7"),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn parses_bracketed_ipv6_with_port() {
        assert_eq!(parse_peer("[::1]:8080"), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    /// Regression guard for NEW-I5: pre-fix this collapsed to `::`
    /// (unspecified IPv6) because `rsplit_once(':')` cut after the
    /// final `:` in the address.
    #[test]
    fn parses_bare_ipv6() {
        assert_eq!(parse_peer("::1"), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            parse_peer("2001:db8::dead:beef"),
            "2001:db8::dead:beef".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn parses_bare_bracketed_ipv6() {
        assert_eq!(parse_peer("[::1]"), IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn empty_falls_back_to_unspecified() {
        assert_eq!(parse_peer(""), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(parse_peer("   "), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn garbage_falls_back_to_unspecified() {
        assert_eq!(parse_peer("not-an-ip"), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            parse_peer("not-an-ip:5555"),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }
}
