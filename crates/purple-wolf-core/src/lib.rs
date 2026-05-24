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

pub mod audit;
pub mod clock;
pub mod config;
pub mod detectors;
pub mod ffi;
pub mod policy;
pub mod request;
