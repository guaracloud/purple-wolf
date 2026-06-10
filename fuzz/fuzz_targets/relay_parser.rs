#![no_main]
//! Fuzz the relay's log-line parser. `parse_line` consumes Traefik log lines
//! whose content embeds attacker-chosen bytes — the request path, query, and
//! User-Agent all land inside the audit JSON the relay extracts via ANSI
//! stripping + balanced-brace scanning. A panic here is a remote relay-DoS
//! triggerable by sending a crafted HTTP request through the WAF. The
//! property: parse_line never panics on arbitrary bytes; it returns Ok or a
//! ParseError, never aborts.
use libfuzzer_sys::fuzz_target;
use purple_wolf_relay::parser;

fuzz_target!(|data: &[u8]| {
    let _ = parser::parse_line(data);
});
