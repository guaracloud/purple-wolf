# Helm install

The production chart is published as an OCI artifact:

```bash
helm install purple-wolf oci://ghcr.io/guaracloud/charts/purple-wolf \
  --version 0.4.1 \
  -f charts/purple-wolf/values.monitor.yaml
```

The default chart deploys the relay with hardened container defaults and renders
monitor/enforce Middleware examples. It does not attach either Middleware to an
IngressRoute and it does not configure a webhook subscriber by default.

## Configure a subscriber

Create a values file that adds a real subscriber and sources its HMAC secret
from Kubernetes:

```yaml
relay:
  secret:
    create: true
    stringData:
      SIEM_HMAC_SECRET: replace-with-generated-secret
  extraEnv:
    - name: SIEM_HMAC_SECRET
      valueFrom:
        secretKeyRef:
          name: purple-wolf-relay-secrets
          key: SIEM_HMAC_SECRET
  config:
    sources:
      - type: log_tail
        path: /var/log/traefik/access.log
        from_beginning: false
    subscribers:
      - id: siem-prod
        url: https://siem.example.com/ingest/purple-wolf
        secret_env: SIEM_HMAC_SECRET
        timeout_ms: 30000
        filter:
          severity_min: high
    relay:
      subscriber_queue: 10000
```

Install with:

```bash
helm upgrade --install purple-wolf oci://ghcr.io/guaracloud/charts/purple-wolf \
  --version 0.4.1 \
  -f values.monitor.yaml \
  -f values.subscriber.yaml
```

## Protect relay admin metrics

`/healthz` and `/readyz` stay unauthenticated for Kubernetes probes. To require
a bearer token for `/metrics` and `/version`, reference the token through the
relay config and expose it as an environment variable:

```yaml
relay:
  secret:
    create: true
    stringData:
      ADMIN_TOKEN: replace-with-generated-token
  extraEnv:
    - name: ADMIN_TOKEN
      valueFrom:
        secretKeyRef:
          name: purple-wolf-relay-secrets
          key: ADMIN_TOKEN
  config:
    relay:
      admin_token_env: ADMIN_TOKEN
```

## Use pinned images

After verifying `release-manifest.json`, pin image digests:

```yaml
relay:
  image:
    repository: ghcr.io/guaracloud/purple-wolf-relay
    digest: sha256:<relay-image-digest>

wasmAsset:
  enabled: true
  image:
    repository: ghcr.io/guaracloud/purple-wolf-wasm
    digest: sha256:<wasm-image-digest>
```

## Validation

```bash
helm lint charts/purple-wolf
helm template purple-wolf charts/purple-wolf
helm template purple-wolf charts/purple-wolf -f charts/purple-wolf/values.monitor.yaml
helm template purple-wolf charts/purple-wolf -f charts/purple-wolf/values.enforce.yaml
helm template purple-wolf charts/purple-wolf -f charts/purple-wolf/values.hardened.yaml
```
