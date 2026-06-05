# purple-wolf local demo

Run the full local stack:

```bash
docker compose -f examples/demo/docker-compose.yml up --build
```

The stack builds the WASM plugin, runs Traefik v3 with the local plugin,
starts a Python backend, tails purple-wolf audit lines with the relay,
and sends HMAC-signed webhooks to the subscriber.

Try these requests from another terminal:

```bash
curl -i http://127.0.0.1:8080/
curl -i 'http://127.0.0.1:8080/?id=1%27%20OR%20%271%27%3D%271'
curl -i 'http://127.0.0.1:8080/?q=%3Cscript%3Ealert(1)%3C/script%3E'
curl -i -A sqlmap http://127.0.0.1:8080/
```

Expected status codes:

| Request | Status |
| --- | --- |
| Benign `/` | `200` |
| SQLi query | `403` |
| XSS query | `403` |
| Scanner User-Agent | `403` |

Expected subscriber output contains JSON lines with
`"schema":"purple-wolf.audit/v1"`, `"action":"block"`, and labels for
`tenant=demo`, `service=local-compose`, and `environment=dev`.

Useful checks:

```bash
curl -fsS http://127.0.0.1:9090/healthz
curl -i http://127.0.0.1:9090/readyz
curl -fsS http://127.0.0.1:9090/version
curl -fsS http://127.0.0.1:9090/metrics | head
docker compose -f examples/demo/docker-compose.yml logs subscriber
```

Troubleshooting:

- Docker must support Compose v2 and `depends_on.condition`.
- The WASM builder downloads WASI SDK v22; if that download fails, rerun
  the command or prebuild `target/wasm32-wasip1/release/purple_wolf_traefik.wasm`.
- If Traefik reports a missing plugin, remove stale volumes with
  `docker compose -f examples/demo/docker-compose.yml down -v` and start again.
- If old images are reused, add `--pull always` or prune the local
  `purple-wolf` demo images before retrying.
