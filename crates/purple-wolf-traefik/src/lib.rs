//! purple-wolf-traefik: http-wasm guest plugin wrapping `purple-wolf-core`.
//!
//! Loaded once into a shared Traefik HA deployment; one plugin instance is
//! constructed per `Middleware` CRD that references it.

mod config;
mod host;

// Entry points added in a later task.
