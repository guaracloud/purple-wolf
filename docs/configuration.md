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

## Per-route specificity

`purple-wolf` does NOT implement per-host/per-path overrides inside the plugin
config. Instead, Traefik's native middleware attachment provides per-route
specificity: define multiple Middlewares with different configs and attach
them to the respective IngressRoute rules.

## Source IP

The plugin derives the source IP from `X-Forwarded-For` (first valid
`IpAddr`) → `X-Real-IP` → the TCP peer. Configure Traefik's `trustedIPs`
on the entrypoint so XFF is honored.

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
