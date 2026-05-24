# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial workspace skeleton.

---

## How to cut a release

1. Update `## [Unreleased]` in this file with a summary of changes under the
   sections of `Added`, `Changed`, `Fixed`, `Removed`.
2. Decide the next version (semver — `cargo-release` defaults to patch).
3. From a clean working tree on a release branch:
   ```bash
   git checkout -b release/v0.2.0
   cargo release 0.2.0 --execute
   ```
   cargo-release will:
   - bump `[workspace.package].version` to `0.2.0` (shared-version)
   - commit `chore(release): 0.2.0` (signed)
   - tag `v0.2.0` (signed)
   - push branch and tag to `origin`
4. The push of the `v*` tag triggers `.github/workflows/release.yml`, which:
   - builds the release `.wasm` against `wasm32-wasip1`
   - computes a SHA256 and cosign-signs the blob (keyless OIDC)
   - creates a GitHub Release with the `.wasm`, `.sha256`, `.sig`, `.pem`
     attached
   - publishes `purple-wolf-core` to crates.io (requires `CARGO_REGISTRY_TOKEN`
     secret configured on the repo)
5. Open a PR back to `main` from the release branch, merge after CI passes.
