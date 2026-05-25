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
  `would_block_rules`.
- **Metrics:** Traefik's built-in per-Middleware metrics; per-rule hit
  counts are derivable from audit-log fields via Loki/Promtail.

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
