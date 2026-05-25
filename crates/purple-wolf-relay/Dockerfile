# syntax=docker/dockerfile:1.6
#
# purple-wolf-relay multi-stage Dockerfile.
#
# Stage 1: build with the workspace's pinned toolchain (matches the
# MSRV the rest of the workspace requires). rustls-tls is enabled so
# the runtime stays free of OpenSSL.
#
# Stage 2: distroless cc-debian12 — small attack surface, no shell,
# no package manager. Non-root user (the distroless image already
# defines uid 65532 / `nonroot`).

ARG RUST_VERSION=1.95
ARG ALPINE_VERSION=3.20

FROM rust:${RUST_VERSION}-slim AS builder
ENV CARGO_TERM_COLOR=always
WORKDIR /src

# Bring in only the manifests first so dependency builds cache cleanly
# across source-only changes.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY fuzz ./fuzz

# Strip vendored fuzz Cargo.toml's reference to the workspace-internal
# crate path that doesn't exist in this build context — fuzz/ ships as
# an excluded workspace member.
RUN cargo build --release -p purple-wolf-relay

FROM gcr.io/distroless/cc-debian12:nonroot

# Default listen for /metrics, /healthz, /readyz, /version.
EXPOSE 9090

# Config file path. Operators bind-mount or ConfigMap-mount a real
# config; this default makes a missing config fail fast at startup.
ENV PURPLE_WOLF_RELAY_CONFIG=/etc/purple-wolf-relay/relay.yaml

# distroless's nonroot user has uid 65532 / gid 65532.
USER nonroot

COPY --from=builder /src/target/release/purple-wolf-relay /usr/local/bin/purple-wolf-relay

ENTRYPOINT ["/usr/local/bin/purple-wolf-relay"]
# K8s probes handle readiness/liveness; distroless has no shell for
# HEALTHCHECK so we rely on the admin endpoints documented in the
# README + examples/relay/k8s/deployment.yaml.
