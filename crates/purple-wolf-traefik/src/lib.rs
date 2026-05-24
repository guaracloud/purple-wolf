//! purple-wolf-traefik: http-wasm guest plugin wrapping `purple-wolf-core`.
//!
//! Loaded once into a shared Traefik HA deployment; one plugin instance is
//! constructed per `Middleware` CRD that references it.

mod config;
mod entry;
mod host;

// Re-export the exported functions so they appear in the .wasm export table.
pub use entry::{handle_request, handle_response};
