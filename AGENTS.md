# Repository Guidelines

## Project Structure & Module Organization

This is a Rust workspace for `purple-wolf`, a Traefik Web Application Firewall
plugin plus a webhook relay. Workspace crates live under `crates/`:
`purple-wolf-core` contains the inspection engine, `purple-wolf-traefik` contains
the WASM/http-wasm adapter, and `purple-wolf-relay` contains the standalone
audit webhook fan-out service. Unit, property, and crate integration tests sit
beside their crates in `crates/*/tests/`. Docker-based end-to-end suites are
separate manifests under `tests/traefik_integration/` and
`tests/relay_integration/`. Operational examples are in `examples/`, docs are in
`docs/`, benchmarks in `benchmarks/`, and fuzz targets/corpora in `fuzz/`.

## Build, Test, and Development Commands

- `cargo test --workspace --all-targets`: run the main workspace test suite.
- `cargo test --workspace --doc`: run doctests.
- `cargo fmt --all --check`: verify formatting.
- `cargo clippy --workspace --all-targets -- -D warnings`: run lints with CI
  warning policy.
- `cargo build -p purple-wolf-traefik --target wasm32-wasip1 --release`: build
  the Traefik WASM plugin; requires `WASI_SDK_PATH`.
- `cargo deny check`: run supply-chain/license checks configured by `deny.toml`.
- `cargo llvm-cov --workspace --fail-under-lines 75`: check the CI coverage
  floor when `cargo-llvm-cov` is installed.

Run ignored Docker suites explicitly, for example:
`cargo test --manifest-path tests/traefik_integration/Cargo.toml -- --ignored --test-threads=1 --nocapture`.

## Coding Style & Naming Conventions

Use Rust 2021 with the pinned toolchain in `rust-toolchain.toml` and MSRV 1.88.
Rely on `rustfmt`; do not hand-format around it. Keep public modules and files
snake_case, crates kebab-case, types/traits PascalCase, and functions/variables
snake_case. Prefer small, testable functions in `purple-wolf-core`; keep adapter
or host-runtime behavior out of the core engine unless it is shared logic.

## Testing Guidelines

Add tests near the affected crate. Use property tests for parser, signature, and
policy invariants, corpus-style tests for security payload regressions, and
Docker integration tests for Traefik or relay wiring changes. For fuzz-sensitive
parsing changes, run relevant targets from `fuzz/`, e.g.
`cargo +nightly fuzz run injection_inspect`.

## Commit & Pull Request Guidelines

Recent history uses conventional prefixes such as `feat:`, `docs:`, `ci:`, and
`revert:`. Keep commits focused and imperative. Pull requests should describe
the behavior change, list verification commands, link related issues, and include
config/docs updates when user-facing policy, Middleware YAML, webhook protocol,
or deployment behavior changes.

## Security & Configuration Tips

Follow `SECURITY.md` for vulnerability reports; do not open public issues for
suspected security bugs. Keep defaults and threat-model claims synchronized
across `THREAT_MODEL.md`, `docs/configuration.md`, examples, and relay docs.
