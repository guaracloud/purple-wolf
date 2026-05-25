# purple-wolf Middleware configuration reference

| field | type | default | meaning |
|---|---|---|---|
| `mode` | `enforce` \| `monitor` | (required) | Global switch. `monitor` never blocks regardless of group modes. |
| `failMode` | `failOpen` \| `failClosed` | `failOpen` | On detector soft failure: continue (`failOpen`) or 403 (`failClosed`). |
| `body.maxInspectBytes` | int | `1048576` | Max bytes of request body inspected. |
| `body.overCap` | `pass` \| `block` | `pass` | When body exceeds cap: `pass` lets Traefik forward; `block` returns 403. |
| `groups.injection` | `{ enabled, mode }` | `{true, enforce}` | SQLi + XSS via libinjection. |
| `groups.signatures` | `{ enabled, mode }` | `{true, enforce}` | Known-bad literal scanner (path traversal, RCE, scanner UAs). |
| `groups.structural` | `{ enabled, mode }` | `{true, monitor}` | Method allowlist + header anomalies. |
| `groups.reputation` | `{ enabled, mode }` | `{false, monitor}` | Per-IP rate limit + IP deny list. |
| `reputation.perSecond` | int | `100` | Per-IP token rate. **Per Traefik pod**; effective rate = configured × pod count. |
| `reputation.denyList` | list[string] | `[]` | IPs (or "ip:port" forms) to deny unconditionally. |
| `xff.trustedHops` | int | `0` | Number of trusted rightmost `X-Forwarded-For` proxies to peel before reading the client IP (drives reputation/audit keying). **`0` = ignore XFF and use the TCP peer** (safe default). Set to the count of trusted proxies between you and the public internet — typically `1` for a single Traefik in front of the plugin. Misconfiguring this is a self-DoS primitive (see Source IP below). |

## Per-route specificity

`purple-wolf` does NOT implement per-host/per-path overrides inside the plugin
config. Instead, Traefik's native middleware attachment provides per-route
specificity: define multiple Middlewares with different configs and attach
them to the respective IngressRoute rules.

## Labels

Every Middleware can attach a `labels` map of free-form `key=value`
strings. The WAF echoes them verbatim in every audit-log entry produced
by that Middleware, giving downstream consumers (log pipelines,
[`purple-wolf-relay`](../crates/purple-wolf-relay/), SIEMs) a stable way
to route or filter on operator-defined metadata.

```yaml
spec:
  plugin:
    purpleWolf:
      mode: enforce
      labels:
        tenant: acme
        service: checkout-api
        environment: prod
        region: us-east-1
        compliance: pci-dss
```

### Schema

| Constraint | Value |
|---|---|
| Key regex | `^[a-z][a-z0-9_.-]{0,62}$` (lowercase ASCII, OpenTelemetry resource-attribute style) |
| Value | any UTF-8 up to 1024 bytes; ASCII control chars stripped at serialize time (CR/LF → `.`) |
| Max keys per Middleware | 32 |
| Max total bytes (keys + values) | 4096 |
| Reserved prefix | `purple_wolf.*` — operator-set keys with this prefix are silently dropped and a warning is emitted to Traefik's log; reserved for fields the WAF or relay sets (`purple_wolf.middleware`, `purple_wolf.router`, …) |

Violating any constraint is a parse error: the Middleware fails to
load and Traefik's plugin-failure path takes over. With the default
`failMode: failOpen` the plugin falls back to a deliberately-noisy
"every detector in monitor" config so verdicts still surface — see
[THREAT_MODEL.md §4](../THREAT_MODEL.md).

### Cardinality warning

Labels become high-cardinality metric dimensions if your relay or log
pipeline derives Prometheus metrics from them. **Do not** set per-user
or per-request values (`user_id`, `request_id`, `session_id`) in
labels. Use them for *bounded* dimensions: tenant, service, environment,
region, team, on-call rotation. The 32-key / 4 KiB caps are an upper
bound, not a target.

### Audit-log shape

When labels are set, the audit-log JSON gains one field with keys in
alphabetical order (so log queries stay grep-able):

```json
{
  "host": "...",
  "path": "...",
  "...": "...",
  "labels": { "environment": "prod", "service": "checkout-api", "tenant": "acme" }
}
```

When no labels are set the field is omitted — v0.2 audit-log shape is
preserved for backward compatibility with existing log queries.

## Source IP

The plugin derives the source IP from `X-Forwarded-For` (after peeling
`xff.trustedHops` trusted rightmost entries) → `X-Real-IP` → the TCP
peer.

**Defaults are safe.** With `xff.trustedHops: 0` (the default), XFF is
ignored entirely — the rate-limiter and audit log key on the TCP peer.
This is correct everywhere, including on a tenant route exposed directly
to the internet.

**Behind a trusted edge (recommended in production):** set
`xff.trustedHops` to the count of proxies between the public internet
and the Traefik pod. With a single Traefik in front of the plugin,
that's `1`. With Cloudflare → ALB → Traefik, it's `2` or `3`.
Independently, configure Traefik's `entryPoints.<name>.forwardedHeaders.
trustedIPs` so Traefik itself respects only XFF entries from its trusted
upstream CIDRs.

**Why this matters:** RFC 7239 specifies the leftmost XFF entry is the
*client-asserted* IP — the least trustworthy hop, because any client
behind your edge can put whatever it wants there. With too high a
`trustedHops` an attacker can pin per-IP rate-limit budgets to a victim
address (impersonation DoS) or rotate IPs in the leftmost slot to
exhaust the rate-limiter's memory. The default `0` removes this entire
class of issue at the cost of having all rate-limit and audit
attribution go to the TCP peer.

## Observability

- **Audit log:** one JSON line per noteworthy request via the host log sink
  (visible in Traefik's logs). Fields: `host`, `path`, `query`, `method`,
  `source_ip`, `action`, `blocked_rule`, `blocked_severity`, `blocked_detail`,
  `would_block_rules`, and (when configured) `labels` — see the
  [Labels](#labels) section above for the schema.
- **Metrics:** Traefik's built-in per-Middleware metrics; per-rule hit
  counts are derivable from audit-log fields via Loki/Promtail.
- **Push delivery:** [`purple-wolf-relay`](../crates/purple-wolf-relay/)
  (v0.3+) tails Traefik's log stream and fans out HMAC-signed webhooks
  to subscribers. Subscriber filters match on the same `labels` map,
  so per-tenant/per-service routing requires no parser plumbing on the
  subscriber side. Wire protocol:
  [docs/webhook-protocol.md](./webhook-protocol.md).

## Detection coverage and limitations

`purple-wolf` uses a hybrid engine: libinjection for SQLi/XSS (context-aware
tokenizer, low false-positive rate) + aho-corasick literal signatures +
structural anomaly checks + per-IP rate limiting.

The engine deliberately does NOT replicate OWASP CRS's regex-rule-per-keyword
detection. CRS catches atomic tokens (`INFORMATION_SCHEMA`, `database(`,
`sleep(20)`) via individual rules; purple-wolf instead aims for high-precision
detection on real-context attacks. On the CRS regression-test corpus
purple-wolf flags ~19% of atomic test inputs — that is by design, not a
regression. The strength is fewer false positives and a much smaller runtime
footprint.
