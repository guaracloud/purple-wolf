# purple-wolf

A fast, low-memory Web Application Firewall delivered as a Traefik plugin.

**Status:** v0.2 in development. See [THREAT_MODEL.md](THREAT_MODEL.md) for what the WAF is and is not designed to catch, and [docs/configuration.md](docs/configuration.md) for the Middleware config reference.

## What it does

`purple-wolf` inspects every HTTP request reaching a route protected by one
of its Middlewares and either lets it through or returns `403 Forbidden`.
Inspection covers headers, URL, query parameters, and the request body (up
to a configurable cap) using a hybrid engine: libinjection (SQLi/XSS),
aho-corasick literal signatures, structural anomaly checks, and per-IP
rate limiting / deny-listing.

## Architecture at a glance

```
internet → Traefik (TLS, routing, your existing setup)
              └─ loads purple-wolf.wasm once at startup
              └─ for each request matching a route that chains a
                 purple-wolf Middleware:
                   instantiate plugin with that Middleware's config
                   → inspect → allow or block → forward to backend
```

- Two crates: [`purple-wolf-core`](crates/purple-wolf-core) (the engine, pure
  Rust, native + `wasm32-wasip1`) and
  [`purple-wolf-traefik`](crates/purple-wolf-traefik) (http-wasm guest plugin).
- Multi-tenant by construction: each `Middleware` CRD is a separate plugin
  instantiation with its own slice of WASM memory.

## Quick start (Traefik)

1. **Get the plugin binary.** Download `purple-wolf.wasm` from the [latest
   GitHub Release](https://github.com/guaracloud/purple-wolf/releases),
   or build it yourself:
   ```bash
   WASI_SDK_PATH=/opt/wasi-sdk cargo build --release \
     -p purple-wolf-traefik --target wasm32-wasip1
   # artifact: target/wasm32-wasip1/release/purple_wolf_traefik.wasm
   ```

2. **Install the plugin into Traefik** (one-time, platform level).
   Place the file at `/plugins-local/src/github.com/guaracloud/purple-wolf/purple-wolf.wasm`
   in your Traefik pods, and declare it in `traefik.yml`:
   ```yaml
   experimental:
     localPlugins:
       purpleWolf:
         moduleName: github.com/guaracloud/purple-wolf
   ```

3. **Apply a Middleware** in your namespace. Start with monitor mode:
   ```bash
   kubectl apply -f examples/middleware-monitor.yaml
   ```
   See [`examples/`](examples/) for the full set:
   - [`middleware-strict.yaml`](examples/middleware-strict.yaml) — block SQLi/XSS, log everything.
   - [`middleware-monitor.yaml`](examples/middleware-monitor.yaml) — log-only rollout.
   - [`middleware-routes.yaml`](examples/middleware-routes.yaml) — attaching different policies to different routes.

4. **Reference the Middleware** in your IngressRoute (`middlewares: [{ name: purple-wolf-monitor }]`).

5. **Tune false positives for ~1 week**, then flip `mode: enforce` and let it
   block.

For the full per-field configuration reference, see
[`docs/configuration.md`](docs/configuration.md).

## Building and testing

```bash
cargo test --workspace                   # unit + property + corpus tests
cargo clippy --workspace --all-targets   # lint
cargo build -p purple-wolf-traefik --target wasm32-wasip1 --release
```

WASM builds require `wasi-sdk`. macOS arm64 dev setup:
```bash
# Download wasi-sdk from https://github.com/WebAssembly/wasi-sdk/releases
export WASI_SDK_PATH=/path/to/wasi-sdk
```

## License

Dual-licensed under MIT OR Apache-2.0. libinjection (vendored C) is BSD-3-Clause.
