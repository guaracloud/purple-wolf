//! purple-wolf-core: hybrid WAF detection engine.
//!
//! This crate is the platform-neutral detection engine used by every
//! purple-wolf deployment (Traefik WASM plugin and, later, sidecar binary).
//! It has no I/O, no async runtime, and compiles to native targets and to
//! `wasm32-wasip1`.

// Modules added by subsequent tasks.
pub mod clock;
pub mod request;
