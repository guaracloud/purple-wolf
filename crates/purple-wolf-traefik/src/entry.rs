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
        Box::new(ReputationDetector::new(cfg.reputation.per_second, ips)),
    ])
}

thread_local! {
    static STATE: OnceCell<(Config, Engine)> = const { OnceCell::new() };
}

fn state<R>(f: impl FnOnce(&Config, &Engine) -> R) -> R {
    STATE.with(|s| {
        let (cfg, engine_) = s.get_or_init(|| {
            let cfg = adapter::parse(&host::config()).unwrap_or_else(|e| {
                host::log(&format!(
                    "purple-wolf: invalid Middleware config ({e}); falling back to global monitor mode — every detector enabled in monitor; verdicts will appear in audit logs but the WAF will not block. Reload Traefik with a valid config to enable enforcement."
                ));
                // Build a deliberately-noisy fallback: every group runs in
                // monitor, so the operator can see verdicts in audit logs and
                // diagnose. Previously this constructed `groups: Default()`
                // which silently disabled every detector — making a bad
                // config a silent no-op WAF.
                Config {
                    mode: Mode::Monitor,
                    fail_mode: FailMode::FailOpen,
                    body: BodyConfig {
                        max_inspect_bytes: 1_048_576,
                        over_cap: OverCap::Pass,
                    },
                    groups: purple_wolf_core::config::Groups::all_monitor(),
                    reputation: ReputationConfig::default(),
                    xff: purple_wolf_core::config::XffConfig::default(),
                }
            });
            let eng = engine(&cfg);
            (cfg, eng)
        });
        f(cfg, engine_)
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
            // Soft failure: detector panic.
            host::log("purple-wolf: soft failure (panic) — applying fail mode");
            state(|cfg, _engine_| match cfg.fail_mode {
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
    state(|cfg, engine_| {
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
        let peer: IpAddr = host::get_source_addr()
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or("")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
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

        // Body (capped).
        let cap = cfg.body.max_inspect_bytes;
        let body = host::read_request_body(cap);
        let over_cap = host::request_body_exceeded(cap);
        if over_cap && cfg.body.over_cap == OverCap::Block {
            host::write_response(403, b"body exceeds inspection cap");
            return Action::Block;
        }
        let body_inspected = !over_cap;

        let req = Request::build(
            &method,
            &host_hdr,
            &path,
            &raw_query,
            headers,
            body,
            body_inspected,
            source_ip,
        );

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

        // Audit log if anything to say.
        let entry = AuditEntry::from(&req, &decision);
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

/// http-wasm exported response hook (unused; we don't modify responses).
#[no_mangle]
pub extern "C" fn handle_response(_req_ctx: u32, _is_error: u32) {}
