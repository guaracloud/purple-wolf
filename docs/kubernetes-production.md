# Kubernetes production packaging

Purple Wolf has two production packaging surfaces:

- Helm: `oci://ghcr.io/guaracloud/charts/purple-wolf`
- Kustomize: `deploy/kubernetes`

The raw files under `examples/` remain educational smoke-test examples.

## Kustomize overlays

```bash
kubectl kustomize deploy/kubernetes/base
kubectl kustomize deploy/kubernetes/overlays/monitor-mode
kubectl kustomize deploy/kubernetes/overlays/enforce-mode
kubectl kustomize deploy/kubernetes/overlays/relay-only
kubectl kustomize deploy/kubernetes/overlays/hardened
```

Apply monitor mode first:

```bash
kubectl apply -k deploy/kubernetes/overlays/monitor-mode
```

Attach `purple-wolf-monitor` to selected Traefik `IngressRoute` objects, review
audit events, tune labels and policy, then switch to the enforce overlay:

```bash
kubectl apply -k deploy/kubernetes/overlays/enforce-mode
```

## Security defaults

The Helm chart and Kustomize base align on:

- non-root UID/GID `65532`
- read-only root filesystem
- dropped Linux capabilities
- `RuntimeDefault` seccomp
- explicit CPU and memory requests/limits
- one relay replica by default
- no default webhook subscriber
- monitor and enforce Middleware examples rendered but not attached

## Relay log source

The default relay config tails `/var/log/traefik/access.log`. In production,
mount the real Traefik audit/log stream into the relay pod by using a shared
volume, sidecar tailer, hostPath, or your platform log-forwarding pattern.

## Secrets

Do not commit real HMAC secrets. Use a Kubernetes Secret, External Secrets
Operator, Vault, SOPS, or your cluster's standard secret manager and expose the
secret as the `secret_env` referenced in `relay.yaml`.
