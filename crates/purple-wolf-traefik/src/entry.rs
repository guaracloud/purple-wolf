//! The http-wasm guest entry: parse config, build a [`Request`], run the
//! [`Engine`], apply policy, either pass through or short-circuit with 403,
//! and emit an audit line via the host log sink.

use crate::{config as adapter, host};
use purple_wolf_core::{
    audit::{self, AuditEntry},
    config::{BodyConfig, Config, FailMode, GroupMode, Mode, OverCap, ReputationConfig},
    detectors::{
        injection::InjectionDetector, reputation::ReputationDetector,
        signatures::SignatureDetector, structural::StructuralDetector, Detector, Engine, Group,
    },
    policy::{self, Action},
    request::{self, Request},
};
use std::cell::OnceCell;
use std::net::IpAddr;

/// Build only the detectors this immutable plugin configuration can execute.
///
/// http-wasm hosts may pool multiple guest instances for one Middleware. Not
/// constructing disabled groups avoids repeating their matcher setup and, in
/// particular, their bounded reputation state for every pooled guest.
fn engine(cfg: &Config, enabled_groups: &[Group]) -> Engine {
    let mut detectors: Vec<Box<dyn Detector>> = Vec::with_capacity(enabled_groups.len());
    for group in enabled_groups {
        match group {
            Group::Injection => detectors.push(Box::new(InjectionDetector)),
            Group::Signatures => detectors.push(Box::new(SignatureDetector::new())),
            Group::Structural => detectors.push(Box::new(StructuralDetector)),
            Group::Reputation => {
                let ips: Vec<IpAddr> = cfg
                    .reputation
                    .deny_list
                    .iter()
                    .filter_map(|ip| ip.parse().ok())
                    .collect();
                detectors.push(Box::new(ReputationDetector::with_capacity(
                    cfg.reputation.per_second,
                    ips,
                    cfg.reputation.max_tracked_ips,
                )));
            }
        }
    }
    Engine::new(detectors)
}

thread_local! {
    static STATE: OnceCell<PluginState> = const { OnceCell::new() };
}

struct PluginState {
    cfg: Config,
    engine: Engine,
    fallback: bool,
    enabled_groups: Vec<Group>,
    group_modes: EffectiveGroupModes,
}

#[derive(Clone, Copy)]
struct EffectiveGroupModes {
    injection: GroupMode,
    signatures: GroupMode,
    structural: GroupMode,
    reputation: GroupMode,
}

impl EffectiveGroupModes {
    fn from_config(cfg: &Config) -> Self {
        Self {
            injection: effective_group_mode(cfg, Group::Injection),
            signatures: effective_group_mode(cfg, Group::Signatures),
            structural: effective_group_mode(cfg, Group::Structural),
            reputation: effective_group_mode(cfg, Group::Reputation),
        }
    }

    fn get(self, group: Group) -> GroupMode {
        match group {
            Group::Injection => self.injection,
            Group::Signatures => self.signatures,
            Group::Structural => self.structural,
            Group::Reputation => self.reputation,
        }
    }
}

fn state<R>(f: impl FnOnce(&PluginState) -> R) -> R {
    STATE.with(|s| {
        let state = s.get_or_init(|| {
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
            let group_modes = EffectiveGroupModes::from_config(&cfg);
            let enabled_groups: Vec<Group> = [
                Group::Injection,
                Group::Signatures,
                Group::Structural,
                Group::Reputation,
            ]
            .into_iter()
            .filter(|group| group_modes.get(*group) != GroupMode::Off)
            .collect();
            let engine = engine(&cfg, &enabled_groups);
            PluginState {
                cfg,
                engine,
                fallback,
                enabled_groups,
                group_modes,
            }
        });
        f(state)
    })
}

/// http-wasm exported entry point invoked once per request.
///
/// Returns the http-wasm "continue" signal (`1` = continue to upstream,
/// `0` = stop, response has already been written by the plugin).
#[no_mangle]
pub extern "C" fn handle_request() -> u64 {
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
            state(|state| match state.cfg.fail_mode {
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
    state(|state| {
        let cfg = &state.cfg;
        // Build header list (lowercased names; values are byte-faithful).
        let headers: Vec<(String, String)> = host::get_request_header_names()
            .into_iter()
            .filter_map(|mut name| {
                let value = host::get_request_header(&name)?;
                name.make_ascii_lowercase();
                Some((name, value))
            })
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
        let (path, raw_query) = uri.split_once('?').unwrap_or((uri.as_str(), ""));
        let method = host::get_method();
        let host_hdr = headers
            .iter()
            .find(|(k, _)| k == "host")
            .map(|(_, v)| v.clone())
            .unwrap_or_default();

        // Body (capped). HTTP/2 and chunked requests need not have a
        // Content-Length header, so framing headers cannot safely prove the
        // absence of a body. Always ask the ABI stream; request buffering is
        // negotiated and consumed bytes are reconstructed through write_body.
        let cap = cfg.body.max_inspect_bytes;
        let preserve_after_cap = cfg.body.over_cap == OverCap::Pass;
        let body_read = match host::read_request_body(cap, preserve_after_cap) {
            Ok(body) => body,
            Err(error) => {
                host::log(&format!(
                    "purple-wolf: request-body inspection failed ({error}); applying safe failure policy"
                ));
                return match (error.forwarding_is_safe(), cfg.fail_mode) {
                    (false, _) => {
                        host::write_response(403, b"request body could not be preserved");
                        Action::Block
                    }
                    (true, FailMode::FailOpen) => Action::Allow,
                    (true, FailMode::FailClosed) => {
                        host::write_response(403, b"inspection failed (fail_closed)");
                        Action::Block
                    }
                };
            }
        };
        let over_cap = body_read.exceeded;
        if over_cap && cfg.body.over_cap == OverCap::Block {
            host::write_response(403, b"body exceeds inspection cap");
            return Action::Block;
        }
        let body_inspected = !body_read.bytes.is_empty();
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
            path,
            raw_query,
            headers,
            body_read.bytes,
            body_inspected,
            source_ip,
        )
        .with_truncated_body(over_cap);

        let verdicts = state.engine.inspect(&req, &state.enabled_groups);
        let decision = policy::decide(verdicts, cfg.mode, |g| state.group_modes.get(g));

        // Audit log if anything to say. `config_fallback` makes every line
        // announce that enforcement is off when we're on the fallback config.
        if decision_is_noteworthy(&decision, state.fallback) {
            let entry = AuditEntry::from_with_labels(&req, &decision, &cfg.labels)
                .with_config_fallback(state.fallback);
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

fn decision_is_noteworthy(decision: &policy::Decision, fallback: bool) -> bool {
    decision.blocked_by.is_some() || !decision.would_block.is_empty() || fallback
}

fn effective_group_mode(cfg: &Config, g: Group) -> GroupMode {
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
