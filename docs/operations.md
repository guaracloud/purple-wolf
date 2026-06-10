# Operations

## Health and readiness

The relay exposes an internal admin listener:

```bash
curl -fsS http://purple-wolf-relay:9090/healthz
curl -i http://purple-wolf-relay:9090/readyz
curl -fsS http://purple-wolf-relay:9090/version
curl -fsS http://purple-wolf-relay:9090/metrics
```

`/readyz` returns ready after the pipeline starts. Use `/healthz` for liveness
and `/readyz` for rollout gating.

If `relay.admin_token_env` or `relay.admin_token_file` is configured, `/metrics`
and `/version` require `Authorization: Bearer <token>`. `/healthz` and
`/readyz` intentionally stay unauthenticated so Kubernetes probes keep working.

## Metrics

Scrape `/metrics` from the relay service. Watch:

- parsed event totals by status
- subscriber delivery attempts and failures
- subscriber queue drops
- DLQ growth
- build/version labels

## Monitor-to-enforce rollout

1. Deploy monitor mode.
2. Attach the monitor Middleware to a small route set.
3. Review audit lines and subscriber events for at least one traffic cycle.
4. Add bounded labels such as `tenant`, `service`, and `environment`.
5. Move one low-risk route to enforce mode.
6. Expand enforce mode after false positives are understood.

## Secret rotation

Create a new HMAC secret in the target subscriber, update the Kubernetes Secret
referenced by `secret_env`, restart the relay, and remove the old secret after
the subscriber's replay window expires.

## Artifact verification

Before upgrading production, verify the release using
[`docs/release-verification.md`](release-verification.md), then deploy
digest-pinned images and a chart version pinned to the verified release.
