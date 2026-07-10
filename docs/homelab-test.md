# Homelab one-shot test deployment

A real-world end-to-end smoke test of purple-wolf v0.4.2 (WAF + relay)
on a Kubernetes cluster. Drives live HTTP traffic through Traefik
with the wasm plugin loaded, watches the relay deliver
HMAC-signed webhooks to a recording subscriber, and reads back the
results.

This document covers the
[`examples/relay/k8s/homelab-test.yaml`](../examples/relay/k8s/homelab-test.yaml)
manifest. It was authored against a K3s 1.30 homelab with
`ingress-nginx` and Pi-hole DNS; the same manifest should work on any
Kubernetes ≥1.27 with an HTTP IngressClass available.

## What it proves

When the test passes, you have evidence that the production-style topology
works end to end:

- The WAF wasm plugin loads inside a real Traefik v3 (not a unit
  test, not docker-compose).
- Operator `labels:` on the Middleware survive Traefik → audit-log
  emit → relay parse → envelope delivery, alphabetically ordered.
- The relay parses Traefik's log format correctly (ANSI escapes,
  surrounding text, embedded JSON).
- HMAC-SHA256 signatures verify against a shared secret.
- The Prometheus `/metrics` surface populates per the docs.

## Architecture

One Pod, four containers + one initContainer, all on localhost
networking with a shared `emptyDir` at `/shared`.

```text
┌─ Pod (purple-wolf-test/pw-test) ────────────────────────────────┐
│ initContainer: stage-plugin                                     │
│   pulls ghcr.io/guaracloud/purple-wolf-wasm:0.4.2, copies the   │
│   .wasm + Traefik plugin manifest into an emptyDir mounted at   │
│   /plugins-local/src/github.com/guaracloud/purple-wolf/         │
├─────────────────────────────────────────────────────────────────┤
│ whoami      :8000  - request echo (the "backend")               │
│ traefik     :8080  - loads the WAF plugin, forwards to          │
│                       localhost:8000, writes host::log calls    │
│                       to /shared/traefik.log                    │
│ relay       :9090  - log_tail source on /shared/traefik.log →   │
│                       parse → HMAC → POST localhost:8090/webhook│
│ subscriber  :8090  - verifies HMAC, records each delivery to    │
│                       /shared/requests.jsonl                    │
└─────────────────────────────────────────────────────────────────┘
   ↑
   Service ClusterIP :8080 → Ingress (nginx-internal): pw-test.home
```

The default `Recreate` deployment strategy is deliberate: the
bookmark file the relay writes into `emptyDir` would diverge across
rolling pods.

## Prerequisites

- A Kubernetes cluster you're allowed to write to. The current
  manifest assumes:
  - `ingressClassName: nginx-internal` (rename if yours differs).
  - DNS that maps a `*.home` (or whatever you change it to) hostname
    to the ingress LB.
- The two GHCR images, public-accessible from the cluster's nodes:
  - `ghcr.io/guaracloud/purple-wolf-relay:0.4.2`
  - `ghcr.io/guaracloud/purple-wolf-wasm:0.4.2`
- `kubectl` configured for the right context. **Double-check** -
  this manifest is for a sandbox cluster, not production.

> **GHCR auth on the homelab.** The K3s nodes have a
> `/etc/rancher/k3s/registries.yaml` that pre-configures GHCR auth
> with a personal PAT. If that PAT doesn't have access to the
> `guaracloud` org packages, every pull returns 403 - even for
> public images - because GHCR treats credential failure as an
> explicit rejection rather than falling back to anonymous. The
> workaround baked into the manifest is `imagePullSecrets:
[ghcr-pull]`, a per-pod docker-registry Secret that overrides the
> node-level auth. See [Troubleshooting](#troubleshooting) below.

## Apply

1. **Create the namespace + the imagePullSecret.** The Secret has to
   exist before the pod tries to pull, so create it in advance from a
   PAT with `read:packages` scope (a `gh auth refresh -s
read:packages` token works):

   ```bash
   kubectl create namespace purple-wolf-test
   kubectl -n purple-wolf-test create secret docker-registry ghcr-pull \
     --docker-server=ghcr.io \
     --docker-username=<your-github-username> \
     --docker-password="$(gh auth token)"
   ```

2. **Apply the manifest:**

   ```bash
   kubectl apply -f examples/relay/k8s/homelab-test.yaml
   ```

3. **Wait for the pod to come up:**

   ```bash
   kubectl -n purple-wolf-test rollout status deploy/pw-test
   kubectl -n purple-wolf-test get pods
   # NAME                       READY   STATUS    RESTARTS   AGE
   # pw-test-xxxxxxxxxx-yyyyy   4/4     Running   0          25s
   ```

## Verify

### Drive the WAF attack matrix

Replace `pw-test.home` with whatever hostname your Ingress
controller publishes (or use `-H 'Host: pw-test.home'` against the LB
IP directly, like the example below).

```bash
LB=<ingress-LB-IP>   # e.g. 192.168.50.200 for nginx-internal

# benign - must pass
curl -sS -o /dev/null -w "benign      → HTTP %{http_code}\n" \
  -H 'Host: pw-test.home' "http://$LB/"

# SQLi in query - must block
curl -sS -o /dev/null -w "sqli        → HTTP %{http_code}\n" \
  -H 'Host: pw-test.home' "http://$LB/?id=1%27%20OR%20%271%27%3D%271"

# XSS in query - must block
curl -sS -o /dev/null -w "xss         → HTTP %{http_code}\n" \
  -H 'Host: pw-test.home' "http://$LB/?q=%3Cscript%3Ealert(1)%3C/script%3E"

# scanner User-Agent - must block
curl -sS -o /dev/null -w "scanner_ua  → HTTP %{http_code}\n" \
  -H 'Host: pw-test.home' -H 'User-Agent: sqlmap/1.7' "http://$LB/"
```

Expected:

```text
benign      → HTTP 200
sqli        → HTTP 403
xss         → HTTP 403
scanner_ua  → HTTP 403
```

### Confirm the relay delivered each block

```bash
kubectl -n purple-wolf-test exec deploy/pw-test -c subscriber \
  -- cat /shared/requests.jsonl | head -20
```

Each line is one delivery. Look for:

- `body.schema == "purple-wolf.audit/v1"`
- `body.labels` contains `{environment: homelab, service:
homelab-test, tenant: acme}` (the Middleware's labels)
- `body.source` contains `middleware: strict-waf`, `router: test`,
  `entry_point: web`, `relay_instance: relay-homelab-test`
- `body.event.action == "block"` and an appropriate `blocked_rule`

If the subscriber received the request _and_ the HMAC verified, the
line was written to the file. If it didn't verify, the subscriber
would have returned 401 and the relay would have retried.

### Scrape the relay's Prometheus surface

```bash
kubectl -n purple-wolf-test port-forward svc/pw-test 19090:9090 &
PF=$!; sleep 2
curl -sS http://127.0.0.1:19090/readyz                    # {"status":"ready"}
curl -sS http://127.0.0.1:19090/metrics | grep '^pwrelay_'
kill $PF
```

`/readyz` and `/healthz` stay unauthenticated even when relay admin auth is
enabled. `/metrics` and `/version` are the admin endpoints protected by an
optional bearer token.

Sane values after driving the three attacks above:

```text
pwrelay_ready 1
pwrelay_source_lines_total{source_id="log_tail:/shared/traefik.log"} 15
pwrelay_parsed_events_total{result="ok"} 3
pwrelay_parsed_events_total{result="not_pw"} 12
pwrelay_subscribers_matched_total{subscriber_id="e2e"} 3
pwrelay_deliveries_total{outcome="delivered",subscriber_id="e2e"} 3
pwrelay_dlq_depth{subscriber_id="e2e"} 0
```

## Teardown

```bash
kubectl delete -f examples/relay/k8s/homelab-test.yaml
kubectl delete secret ghcr-pull -n purple-wolf-test  # if you created it manually
kubectl delete namespace purple-wolf-test            # belt-and-braces
```
