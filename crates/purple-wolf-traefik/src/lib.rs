//! purple-wolf-traefik: http-wasm guest plugin wrapping `purple-wolf-core`.
//!
//! Loaded once into a shared Traefik HA deployment; one plugin instance is
//! constructed per `Middleware` CRD that references it.

// Panic-surface discipline (see purple-wolf-core/src/lib.rs for the full
// rationale): unwinding is unavailable on `wasm32-wasip1`, so a panic in the
// guest traps the instance and bypasses `failMode`. Deny the panic-producing
// patterns in production paths; test modules opt out.
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::expect_used)]

mod config;
mod entry;
mod host;

// Re-export the exported functions so they appear in the .wasm export table.
pub use entry::{handle_request, handle_response};
