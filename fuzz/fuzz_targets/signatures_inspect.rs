#![no_main]
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::detectors::{Detector, signatures::SignatureDetector};
use purple_wolf_core::request::Request;
use std::net::{IpAddr, Ipv4Addr};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data).into_owned();
    let req = Request::build("GET", "h", "/", &format!("q={s}"), vec![], vec![], false,
        IpAddr::V4(Ipv4Addr::LOCALHOST));
    let _ = SignatureDetector::new().inspect(&req);
});
