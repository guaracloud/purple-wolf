#![no_main]
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::request::Request;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    // Split the input bytes into rough "fields" the parser would otherwise
    // receive from a host. The property: never panic.
    let s = String::from_utf8_lossy(data);
    let parts: Vec<&str> = s.split('|').collect();
    let method = parts.first().copied().unwrap_or("GET");
    let host   = parts.get(1).copied().unwrap_or("");
    let path   = parts.get(2).copied().unwrap_or("/");
    let query  = parts.get(3).copied().unwrap_or("");
    let body   = parts.get(4).map(|p| p.as_bytes().to_vec()).unwrap_or_default();
    let _ = Request::build(method, host, path, query, vec![], body, true,
        IpAddr::V4(Ipv4Addr::LOCALHOST));
});
