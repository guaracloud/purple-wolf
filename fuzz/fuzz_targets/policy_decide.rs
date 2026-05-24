#![no_main]
use libfuzzer_sys::fuzz_target;
use purple_wolf_core::config::{GroupMode, Mode};
use purple_wolf_core::detectors::{Group, Severity, Verdict};
use purple_wolf_core::policy;

fuzz_target!(|data: &[u8]| {
    let mut verdicts = Vec::new();
    for b in data.iter() {
        let g = match b % 4 {
            0 => Group::Injection, 1 => Group::Signatures,
            2 => Group::Structural, _ => Group::Reputation,
        };
        verdicts.push(Verdict { group: g, rule: "f", severity: Severity::High, detail: "f".into() });
    }
    let mode = if data.first().map_or(false, |b| b & 1 == 0) { Mode::Enforce } else { Mode::Monitor };
    let _ = policy::decide(verdicts, mode, |_| GroupMode::Enforce);
});
