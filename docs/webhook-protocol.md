# `purple-wolf.audit/v1` webhook protocol

**Status:** stable - schema bumps require a documented migration window.
**Audience:** subscriber implementers. The relay sends; the subscriber receives.
**Producer:** [`purple-wolf-relay`](../crates/purple-wolf-relay/) v0.1.0+.

This document is the only contract between the relay and a subscriber.
You do not need to read the relay's source to implement a compliant
subscriber.

---

## 1. Envelope schema v1

Every webhook body is a single JSON object matching this shape:

```json
{
  "schema": "purple-wolf.audit/v1",
  "event_id": "01HXYZ7F8GZG23P4M2RKN9Y4QF",
  "delivery_id": "01HXYZ7F8GZG23P4M2RKN9Y4QG",
  "delivered_at": "2026-05-25T17:30:02.123Z",
  "attempt": 1,
  "labels": { "environment": "prod", "service": "checkout-api", "tenant": "acme" },
  "source": {
    "middleware": "strict-waf",
    "router": "checkout",
    "entry_point": "web",
    "relay_instance": "relay-abc-1"
  },
  "event": {
    "host": "checkout.acme.example",
    "path": "/api/v1/cart",
    "query": "id=1%27+OR+%271%27%3D%271",
    "method": "POST",
    "source_ip": "203.0.113.7",
    "action": "block",
    "blocked_rule": "injection/sqli",
    "blocked_severity": "critical",
    "blocked_detail": "SQLi in field: …",
    "would_block_rules": ["reputation/rate_limited"]
  }
}
```

### Fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `schema` | string | yes | Always `"purple-wolf.audit/<MAJOR>"`. v1 today. Reject if the major doesn't match what your subscriber implements. |
| `event_id` | ULID string | yes | **Stable across retries.** Subscribers MUST dedupe on this. |
| `delivery_id` | ULID string | yes | **Changes per attempt.** Useful only for subscriber-side logging - do not use for dedup. |
| `delivered_at` | RFC 3339 UTC | yes | When the relay started this attempt. Not the same as `event.*` timestamps. |
| `attempt` | int ≥ 1 | yes | 1-based retry counter; matches the `X-PurpleWolf-Attempt` header. |
| `labels` | object<string,string> | omitted-when-empty | Operator-supplied labels from the source Middleware. See [configuration.md §Labels](./configuration.md#labels). |
| `source.middleware` | string \| null | yes | Traefik Middleware name (without the `@file` / `@kubernetescrd` suffix). May be null if the relay couldn't extract it from the log line. |
| `source.router` | string \| null | yes | Traefik router name (suffix stripped). |
| `source.entry_point` | string \| null | yes | Traefik entry-point name. |
| `source.relay_instance` | string | yes | Stable identifier for this relay instance. Useful for cluster-wide dedup when running multiple relays. |
| `event` | object | yes | Verbatim purple-wolf audit fields. **Treat as forward-compatible**: new optional fields may appear in minor versions without a schema bump. |

### Forward compatibility within v1

The relay guarantees:

- All v1 envelopes will contain the fields listed above.
- New optional fields may be added under `event.*` or `source.*` without
  a schema bump. Subscribers MUST ignore unknown fields.
- Existing fields will not change type or be removed within v1.

Anything that *would* break those guarantees ships as `purple-wolf.audit/v2`,
side-by-side with v1 for a documented migration window (see §6).

---

## 2. HTTP semantics

### Request

```
POST <subscriber.url>
Content-Type: application/json
User-Agent: purple-wolf-relay/<version>
X-PurpleWolf-Schema: purple-wolf.audit/v1
X-PurpleWolf-Event-Id: 01HXYZ...
X-PurpleWolf-Delivery-Id: 01HXYZ...
X-PurpleWolf-Attempt: 1
X-PurpleWolf-Timestamp: 1748194202
X-PurpleWolf-Signature: sha256=<lowercase hex HMAC>
```

The relay does NOT follow redirects (3xx responses are treated as
delivery failure). Configure your URL to be the final destination.

### Response (subscriber → relay)

| Status | Relay interpretation |
|---|---|
| `2xx` | Delivered; relay marks the attempt complete and discards the envelope. |
| `408 Request Timeout` | Retryable; relay re-attempts per its retry policy. |
| `429 Too Many Requests` | Retryable; relay honors `Retry-After` when present (capped at the configured `max_delay_ms`). |
| `5xx` | Retryable; relay re-attempts per its retry policy. |
| `3xx` | **Failure.** Relay does not follow redirects. |
| `4xx` (except 408, 429) | **Permanent failure.** Envelope goes to the DLQ; no retries. |
| network error / connection reset | Retryable. |
| timeout (default 30s) | Retryable. |

Response bodies are not inspected - keep them small to save bandwidth.

---

## 3. HMAC verification

**Algorithm:** HMAC-SHA256.

**Signed payload:** the literal byte concatenation

```
<X-PurpleWolf-Timestamp>.<request body bytes>
```

where the timestamp is the ASCII decimal-string value of the
`X-PurpleWolf-Timestamp` header (Unix seconds). The relay enforces
that the body is sent verbatim; subscribers MUST sign the **raw request
body**, not a re-serialized JSON form.

**Header format:**

```
X-PurpleWolf-Signature: sha256=<lowercase hex>
```

**Subscriber requirements:**

1. **Constant-time compare.** Use a constant-time HMAC compare (e.g.,
   `hmac.compare_digest` in Python, `subtle.ConstantTimeCompare` in Go,
   `timingSafeEqual` in Node). Plain string equality leaks timing.
2. **Verify timestamp skew.** Reject if `|now - timestamp| > 300s`
   (default 5 minutes). The timestamp is part of the HMAC input, so
   a captured request can't be replayed outside the window.
3. **Use the raw body.** If your framework parses the body before
   handing it to you, re-serialization will change byte-for-byte
   output and the signature will not verify.

**Secret rotation.** Subscribers SHOULD support an overlap window
during rotation: accept signatures verified by **either** the old or
new secret while the operator flips the relay's config. A safe pattern:
keep two secrets in your subscriber and accept either; expire the old
one after the rotation window closes.

---

## 4. Idempotency

The relay is at-least-once. Subscribers achieve at-most-once (and thus
exactly-once) by deduping on `event_id`.

**Required:**

- Store `event_id` for at least the relay's max retry window (default
  ~10 minutes for `max_attempts=8, max_delay_ms=600_000`). 24 hours is
  a safe default that absorbs longer outages on the subscriber side.
- On a duplicate, respond `200 OK` with no side-effect - the relay
  treats this as "delivered" and stops retrying.

**Recommended:**

- Even with dedup, make your handler idempotent at the side-effect
  level. Dedup catches retries; idempotent handlers catch the case
  where you 200'd before persisting and crashed.

---

## 5. Retry semantics (informational)

The relay's default retry policy:

- Exponential backoff with ±20% jitter.
- Base delay: 500ms.
- Max delay: 10 minutes (`max_delay_ms`).
- Max attempts: 8 (configurable per-subscriber).
- After max attempts the envelope is moved to the per-subscriber DLQ.

Subscribers **MUST NOT** assume any specific retry schedule. The
contract is "at least once for up to `max_attempts × max_delay_ms`",
not a specific backoff curve.

---

## 6. Versioning policy

- The `schema` field's MAJOR identifies the protocol generation.
- Within a MAJOR, only additive changes (new optional fields) are
  permitted. Subscribers MUST ignore unknown fields.
- Removing a field, changing a type, or changing the semantics of a
  field requires a MAJOR bump.
- During a migration window the relay can be configured to deliver
  both `vN` and `vN+1` envelopes to the same subscriber URL with
  different `schema` headers; subscribers can fan-in on `schema`.

---

## 7. Reference subscriber implementations

Three small reference implementations live in
[`crates/purple-wolf-relay/examples/subscribers/`](../crates/purple-wolf-relay/examples/subscribers/).
Each one verifies the signature, checks the timestamp skew, dedupes
on `event_id`, and responds 200 on success / 5xx on transient error.

### Python (Flask)

```python
import hashlib, hmac, json, os, time
from collections import OrderedDict
from flask import Flask, request, abort

SECRET = os.environ["PURPLEWOLF_SECRET"].encode()
SKEW_S = 300                       # 5 minutes
SEEN: "OrderedDict[str, float]" = OrderedDict()  # event_id → ts; replace with Redis in prod
SEEN_CAP = 10_000

app = Flask(__name__)

@app.post("/webhook")
def receive():
    ts = request.headers.get("X-PurpleWolf-Timestamp", "")
    sig = request.headers.get("X-PurpleWolf-Signature", "")
    eid = request.headers.get("X-PurpleWolf-Event-Id", "")
    if not (ts.isdigit() and sig.startswith("sha256=") and eid):
        abort(400)
    if abs(time.time() - int(ts)) > SKEW_S:
        abort(401)  # replay protection
    body = request.get_data()
    expected = "sha256=" + hmac.new(
        SECRET, f"{ts}.".encode() + body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, sig):
        abort(401)
    if eid in SEEN:
        return ("", 200)  # dedup; idempotent ack
    SEEN[eid] = time.time()
    if len(SEEN) > SEEN_CAP:
        SEEN.popitem(last=False)
    event = json.loads(body)
    # ... your handler ...
    return ("", 200)
```

### Go (net/http)

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "net/http"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"
)

var (
    secret = []byte(os.Getenv("PURPLEWOLF_SECRET"))
    seen   sync.Map  // event_id → seen-at; for prod use a TTL store
    skew   = 300 * time.Second
)

func receive(w http.ResponseWriter, r *http.Request) {
    tsHdr := r.Header.Get("X-PurpleWolf-Timestamp")
    sig := r.Header.Get("X-PurpleWolf-Signature")
    eid := r.Header.Get("X-PurpleWolf-Event-Id")
    if tsHdr == "" || !strings.HasPrefix(sig, "sha256=") || eid == "" {
        http.Error(w, "bad headers", http.StatusBadRequest); return
    }
    ts, err := strconv.ParseInt(tsHdr, 10, 64)
    if err != nil {
        http.Error(w, "bad ts", http.StatusBadRequest); return
    }
    if abs(time.Now().Unix()-ts) > int64(skew.Seconds()) {
        http.Error(w, "skew", http.StatusUnauthorized); return
    }
    body, _ := io.ReadAll(r.Body)
    mac := hmac.New(sha256.New, secret)
    mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
    mac.Write(body)
    expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
    if !hmac.Equal([]byte(expected), []byte(sig)) {
        http.Error(w, "sig", http.StatusUnauthorized); return
    }
    if _, dup := seen.LoadOrStore(eid, time.Now()); dup {
        w.WriteHeader(http.StatusOK); return
    }
    // ... your handler ...
    w.WriteHeader(http.StatusOK)
}

func abs(x int64) int64 { if x < 0 { return -x }; return x }

func main() {
    http.HandleFunc("/webhook", receive)
    _ = http.ListenAndServe(":8080", nil)
}
```

### TypeScript (Hono)

```ts
import { Hono } from "hono";
import { createHmac, timingSafeEqual } from "node:crypto";

const SECRET = Buffer.from(process.env.PURPLEWOLF_SECRET!);
const SKEW_S = 300;
const seen = new Map<string, number>();
const SEEN_CAP = 10_000;

const app = new Hono();

app.post("/webhook", async (c) => {
  const ts = c.req.header("x-purplewolf-timestamp") ?? "";
  const sig = c.req.header("x-purplewolf-signature") ?? "";
  const eid = c.req.header("x-purplewolf-event-id") ?? "";
  if (!/^\d+$/.test(ts) || !sig.startsWith("sha256=") || !eid) {
    return c.text("bad headers", 400);
  }
  if (Math.abs(Date.now() / 1000 - Number(ts)) > SKEW_S) {
    return c.text("skew", 401);
  }
  const body = Buffer.from(await c.req.arrayBuffer());
  const expected =
    "sha256=" +
    createHmac("sha256", SECRET).update(`${ts}.`).update(body).digest("hex");
  if (
    expected.length !== sig.length ||
    !timingSafeEqual(Buffer.from(expected), Buffer.from(sig))
  ) {
    return c.text("sig", 401);
  }
  if (seen.has(eid)) return c.text("", 200);
  seen.set(eid, Date.now());
  if (seen.size > SEEN_CAP) seen.delete(seen.keys().next().value!);
  // ... your handler ...
  return c.text("", 200);
});

export default app;
```

---

## 8. Security checklist for subscribers

- [ ] Verify HMAC signature on every request. Do not trust source IP,
      Host header, or any other transport hint.
- [ ] Compare HMACs in constant time.
- [ ] Check `|now - X-PurpleWolf-Timestamp| ≤ 300s` for replay
      protection. Sync your clock (NTP/Chrony).
- [ ] Dedupe on `event_id`. At-least-once → exactly-once shifts the
      burden to you; budget for it.
- [ ] Sign the **raw** request body. Don't re-serialize after parsing.
- [ ] Respond within 30s (default relay timeout). Long-running side
      effects belong in a queue, not in the request handler.
- [ ] Support an overlap window during secret rotation. Two secrets
      simultaneously valid is the standard pattern.
- [ ] Make your handler idempotent at the side-effect level (DB
      writes, message emits) - dedup catches retries, idempotency
      catches partial successes.
- [ ] On unrecoverable application errors, return 5xx (the relay
      retries) - not 4xx (the relay sends to DLQ).
- [ ] Bind your endpoint TLS-only in production. The relay's HMAC
      gives integrity + authenticity, not confidentiality.

---

## 9. Error handling table (relay's view)

| Subscriber outcome | Relay action |
|---|---|
| 2xx | Mark delivered. |
| 408, 429, 5xx | Retry with backoff. |
| 4xx (not 408/429) | Move to DLQ. Operator action required. |
| 3xx | Treated as failure. Move to DLQ. (Relay does not follow redirects.) |
| Network error / connection reset | Retry with backoff. |
| TLS handshake failure | Retry with backoff. |
| Subscriber timeout (default 30s) | Retry with backoff. |
| Max attempts exhausted | Move to DLQ. |

---

*See [configuration.md](./configuration.md#labels) for how operators set
the `labels` field this protocol carries. See the relay README for
operational concerns (DLQ replay, secret rotation procedure, metrics).*
