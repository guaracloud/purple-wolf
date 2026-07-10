//! purple-wolf-core: hybrid WAF detection engine.
//!
//! Build a [`request::Request`] from raw HTTP fields, run [`detectors::Engine::inspect`],
//! and turn the verdicts into an action with [`policy::decide`]. The
//! [`audit::AuditEntry`] type captures one log-worthy record per decision.
//!
//! Embedders own all I/O, configuration loading, and result delivery. This
//! crate has no async runtime, no networking, and no global state. It
//! compiles to native targets and to `wasm32-wasip1`.
//!
//! # Cargo features
//!
//! The default `toml-config` feature adds `Config::parse` to
//! [`config::Config`] for native embedders. JSON-only guests can disable
//! default features to omit the TOML parser dependency;
//! [`config::Config::parse_json`] remains available.
//!
//! # Example: inspect a request
//!
//! ```
//! use purple_wolf_core::request::Request;
//! use purple_wolf_core::detectors::{Engine, Group};
//! use purple_wolf_core::detectors::injection::InjectionDetector;
//! use purple_wolf_core::policy;
//! use purple_wolf_core::config::{Mode, GroupMode};
//! use std::net::{IpAddr, Ipv4Addr};
//!
//! let req = Request::build(
//!     "GET", "example.com", "/search",
//!     "q=%27%20OR%201%3D1",
//!     vec![],
//!     vec![],
//!     false,
//!     IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
//! );
//! let engine = Engine::new(vec![Box::new(InjectionDetector)]);
//! let verdicts = engine.inspect(&req, &[Group::Injection]);
//! let decision = policy::decide(verdicts, Mode::Enforce, |_| GroupMode::Enforce);
//! assert_eq!(decision.action, policy::Action::Block);
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::missing_crate_level_docs)]
// Panic-surface discipline. Unwinding is unavailable on `wasm32-wasip1`
// (`panic = "abort"`), so a panic in detection logic does not unwind into
// the guest's `catch_unwind` — it traps the whole Wasm instance and the
// request is handled by Traefik's plugin-failure path, *bypassing* the
// configured `failMode`. The only robust defense is to structurally exclude
// panics from production code paths. These denies enforce that; test modules
// opt back out with `#![allow(...)]` since panicking is how tests assert.
//
// `clippy::indexing_slicing` is deliberately NOT denied: it fires on
// provably-bounded slab/index access (e.g. the reputation LRU's intrusive
// links) where `[]` is clearer than `.get().expect()` and would just trade
// one lint for another. Reach for `.get()` on any *attacker-influenced*
// index; the existing sites are internal invariants.
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::expect_used)]

pub mod audit;
pub mod clock;
pub mod config;
pub mod detectors;
pub mod ffi;
pub mod policy;
pub mod request;
