#![no_main]
//! Fuzz `request::client_ip`: the XFF/X-Real-IP trust-model resolver. This is
//! the most attacker-adjacent parser in the engine — `X-Forwarded-For` is
//! fully attacker-controlled, and the function does arithmetic on the
//! `trusted_hops` count against a comma-split chain. The property: never
//! panic, for any header bytes and any hop count.
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::request;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    // First line (if any) seeds the hop count; the rest are header lines of
    // the form `name:value`. This lets the fuzzer explore both the trust
    // arithmetic and malformed header shapes.
    let mut lines = s.split('\n');
    let trust_hops = lines
        .next()
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(0)
        // Bound so we exercise the peeling logic, not allocator pressure.
        .min(64);
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect();
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let _ = request::client_ip(&headers, peer, trust_hops);
});
