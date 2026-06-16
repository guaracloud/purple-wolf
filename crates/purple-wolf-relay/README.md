# purple-wolf-relay

A standalone, vendor-neutral webhook fan-out for
[purple-wolf](https://github.com/guaracloud/purple-wolf) WAF audit
events.

The WAF (a Traefik http-wasm plugin) emits structured audit-log lines on
every blocked or noteworthy request. The relay tails Traefik's log
stream, parses the purple-wolf JSON envelope, applies optional label
enrichment, and fans out HMAC-signed HTTP POST webhooks to one or more
operator-configured subscribers - with retries, per-subscriber bounded
queues, and a dead-letter queue.

**Status:** pre-1.0 - protocol stable, implementation evolving.

- Protocol contract: [`docs/webhook-protocol.md`](../../docs/webhook-protocol.md)
- Config reference: [`docs/configuration.md`](../../docs/configuration.md)
- Threat model: [`THREAT_MODEL.md`](../../THREAT_MODEL.md)

## Quick start

```bash
export EXAMPLE_HMAC_SECRET="$(openssl rand -hex 32)"
cargo run -p purple-wolf-relay -- \
  --config crates/purple-wolf-relay/examples/config.minimal.yaml \
  --validate-only
```

A minimal config:

```yaml
sources:
  - type: stdin
subscribers:
  - id: example
    url: https://hooks.example.com/webhook
    secret_env: EXAMPLE_HMAC_SECRET
```

## Architecture

```
[Traefik stdout]
      │
      ▼
[source] → [parser] → [enrichers] → [subscribers (filter + HMAC + retry + DLQ)]
                                                    │
                                                    └── HMAC-signed HTTP POST
```

The pipeline runs as a `tokio` task graph: one task per source, one
parser/enricher task, and one task per subscriber with its own bounded
mpsc queue so a slow subscriber cannot backpressure fast subscribers.

## What this is not

- Not a SIEM. The DLQ is bounded; long-term event storage is the
  subscriber's job.
- Not a multi-tenant SaaS. Each deployment runs its own relay instance.
- Not a transformation pipeline. If you need to reshape, do it at the
  subscriber or upstream with Vector / Fluent Bit.

## License

Dual-licensed under MIT or Apache-2.0, same as the rest of the
workspace.
