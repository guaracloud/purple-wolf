//! `purple-wolf-validate` — offline validator for a Traefik plugin config.
//!
//! Parses the JSON config Traefik would hand the guest, using the *exact*
//! same adapter the live plugin uses, and reports whether it would load. This
//! lets operators gate Middleware changes in CI before a bad config silently
//! demotes the WAF to monitor-only at runtime (the all-monitor fallback).
//!
//! Usage:
//!   purple-wolf-validate path/to/config.json
//!   cat config.json | purple-wolf-validate           # reads stdin when no arg
//!
//! Exit codes: 0 = valid (warnings, if any, printed to stderr); 1 = invalid;
//! 2 = usage / I/O error. Mirrors the relay's `--validate-only`.

use std::io::Read;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    let bytes = match read_input(arg.as_deref()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("purple-wolf-validate: {e}");
            return ExitCode::from(2);
        }
    };

    match purple_wolf_traefik::validate_config(&bytes) {
        Ok(warnings) => {
            for w in &warnings {
                eprintln!("warning: {w}");
            }
            println!("ok: config is valid{}", suffix(warnings.len()));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: config is invalid: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Read the config from `path`, or from stdin when `path` is `None` or `-`.
fn read_input(path: Option<&str>) -> Result<Vec<u8>, String> {
    match path {
        None | Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("reading stdin: {e}"))?;
            Ok(buf)
        }
        Some(p) => std::fs::read(p).map_err(|e| format!("reading {p}: {e}")),
    }
}

fn suffix(n: usize) -> String {
    match n {
        0 => String::new(),
        1 => " (1 warning)".to_string(),
        n => format!(" ({n} warnings)"),
    }
}
