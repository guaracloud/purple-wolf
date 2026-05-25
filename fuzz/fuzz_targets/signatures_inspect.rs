#![no_main]
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::detectors::{Detector, signatures::SignatureDetector};
use purple_wolf_core::request::Request;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::OnceLock;

// NEW-M4: cache the detector across fuzz iterations. `SignatureDetector::new`
// builds the aho-corasick matcher every call; doing that per-iteration cut
// throughput ~13x vs the sibling fuzz targets (REVIEW.md §7.8). The matcher
// itself is what we're fuzzing, not its construction.
static DETECTOR: OnceLock<SignatureDetector> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data).into_owned();
    let req = Request::build("GET", "h", "/", &format!("q={s}"), vec![], vec![], false,
        IpAddr::V4(Ipv4Addr::LOCALHOST));
    let det = DETECTOR.get_or_init(SignatureDetector::new);
    let _ = det.inspect(&req);
});
