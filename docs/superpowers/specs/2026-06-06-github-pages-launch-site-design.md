# Purple Wolf GitHub Pages Launch Site Design

## Purpose

Create a single-page GitHub Pages site that presents Purple Wolf as a credible,
approachable OSS WAF for Traefik. The page should help three audiences decide
what to do next:

- Security engineers should understand the detection scope, verification story,
  benchmark boundaries, and relay-to-SIEM path.
- DevOps and Kubernetes operators should see safe installation paths, hardened
  defaults, digest-pinned deployment, and monitor-to-enforce rollout.
- Traefik users should quickly understand how the WASM plugin fits into their
  existing routing setup and how to try it locally.

The page is not a replacement for the docs. It is the front door that sends
users to the right docs, release assets, and quickstart commands.

## Positioning

Primary headline:

```text
A fast, verifiable WAF for Traefik.
```

Supporting copy:

```text
Purple Wolf runs as a Traefik WASM plugin, ships signed release artifacts,
publishes SBOMs and digest-pinned images, and supports a monitor-first
Kubernetes rollout through Helm and Kustomize.
```

Core message:

```text
Monitor first. Enforce deliberately.
```

The site must avoid exaggerated security claims. It should not use phrases like
"blocks everything", "military-grade", "enterprise-ready", or "next-generation
AI WAF". It should be direct about what Purple Wolf does, how it is packaged,
and how users verify what they deploy.

## Tone And Brand

The tone is "OSS launch page plus benchmark credibility":

- approachable enough for new Traefik users
- precise enough for security engineers
- operational enough for Kubernetes teams
- transparent about threat-model boundaries

The page should feel polished and memorable, but not decorative for its own
sake. The strongest design signal is credibility: measured claims, clear
commands, visible release artifacts, and an honest benchmark snapshot.

## Information Architecture

### 1. Hero

The hero should communicate the product in one viewport:

- brand name: Purple Wolf
- headline: "A fast, verifiable WAF for Traefik."
- concise product explanation
- primary CTA: "Try the demo"
- secondary CTAs: "View v0.3 release" and "Install with Helm"
- trust row:
  - Traefik WASM plugin
  - signed artifacts
  - SBOMs
  - Helm OCI chart
  - monitor-first rollout

The hero should also include a compact request-path visual:

```text
request
  |
  v
+---------+      +-------------------+      +---------+
| Traefik | ---> | Purple Wolf WASM  | ---> | Backend |
+---------+      +-------------------+      +---------+
                         |
                         v
                 +---------------+
                 | Relay / SIEM  |
                 +---------------+
```

The final implementation can render this as structured HTML/CSS rather than
literal ASCII, but it should preserve the same mental model.

### 2. Audience Paths

Three concise audience blocks:

- Security engineers:
  - threat-model link
  - signed release artifacts
  - SBOMs
  - HMAC-signed webhook relay
- DevOps and Kubernetes operators:
  - Helm OCI chart
  - Kustomize overlays
  - hardened defaults
  - digest-pinned deployment
- Traefik users:
  - WASM plugin
  - Middleware examples
  - local demo
  - monitor/enforce modes

These blocks should not be generic icon cards. Each should have a distinct
layout treatment or compact checklist so the section does not look templated.

### 3. Benchmark Snapshot

This is the spine of the page. It should summarize the benchmark without
overclaiming:

- isolated WAF overhead: `+0.1-0.2 ms p99`
- sustained throughput under tested resources: `~8,000 RPS`
- memory during soak: `80-96 MiB`
- detection comparison in the same Traefik http-wasm shape:
  - Purple Wolf: `14.55%`
  - Coraza inline-PL1 http-wasm: `6.11%`

Required caveat:

```text
Same plugin shape, same resource budget, same yardstick. This is not a claim
that Purple Wolf is better than every Coraza deployment or every WAF mode.
```

The section should link to `docs/benchmark.md`.

### 4. How It Works

Explain the system in operational terms:

```text
Internet -> Traefik -> Purple Wolf WASM -> backend
                         |
                         v
                     Relay -> SIEM / Slack bridge / tenant webhook
```

The section should make clear that the WAF inspection path and the webhook relay
are separate responsibilities:

- the WASM plugin inspects requests and allows or blocks
- the relay tails audit output and fans out signed webhook events

### 5. Install Paths

Show three install paths with copyable commands:

Local demo:

```bash
docker compose -f examples/demo/docker-compose.yml up --build
```

Helm:

```bash
helm install purple-wolf oci://ghcr.io/guaracloud/charts/purple-wolf \
  --version 0.3.0 \
  -f charts/purple-wolf/values.monitor.yaml
```

Kustomize:

```bash
kubectl apply -k deploy/kubernetes/overlays/monitor-mode
```

The page should make clear that production users should verify artifacts and use
digest-pinned images from the release manifest.

### 6. Verify Before Production

This section should make the release chain visible:

- `release-manifest.json`
- Cosign blob and image signatures
- SPDX SBOMs
- GHCR image digests
- Helm OCI chart digest

It should link to `docs/release-verification.md` and the `v0.3.0` GitHub
release.

### 7. Monitor-To-Enforce Rollout

Explain the recommended adoption path:

1. install monitor-mode examples
2. attach `purple-wolf-monitor` to selected routes
3. inspect audit events and webhook output
4. tune policy and body limits
5. opt into enforce mode route by route

The section should reinforce that enforce mode is explicit and deliberate.

### 8. Footer

Footer links:

- GitHub repository
- v0.3.0 release
- documentation
- threat model
- configuration reference
- benchmark
- license

## Visual Direction

Use a light-first product/OSS page. The palette should be mostly neutral with
purple as a restrained accent and one secondary verification/status accent.
Avoid a dark neon hacker aesthetic and avoid one-note purple saturation.

Design constraints:

- no gradient text
- no decorative glow/orb backgrounds
- no generic icon-card grid repeated throughout the page
- no vague stock imagery
- no cards nested inside cards
- body copy should stay readable at 65-75 characters per line
- command blocks must be easy to scan and copy visually
- benchmark numbers must not overwhelm the threat-model caveat

Typography should feel crisp and technical without falling into generic
monospace-as-technology styling. Use a distinctive display face and a readable
body face during implementation, selected against the impeccable font rules.

## Technical Shape

The implementation should be simple and static for GitHub Pages.

Preferred shape:

- a dedicated static site under `site/`
- plain HTML/CSS/JavaScript or a minimal build step only if necessary
- GitHub Pages workflow publishing the built static output
- no heavyweight framework unless a repo constraint appears during planning

The site should not disturb existing Rust workspace behavior. It should be
isolated from Cargo, release packaging, and current examples.

## Required Content Updates

The implementation should also update the README status line from `v0.3 in
development` to released wording, because the public landing page should not
contradict the repository front page.

Recommended README wording:

```text
Status: v0.3 released (audit labels, webhook relay, signed release artifacts,
SBOMs, Helm OCI chart, and Kubernetes packaging).
```

## Accessibility And Responsiveness

The page must work well on mobile and desktop:

- meaningful heading order
- keyboard-accessible links and buttons
- contrast suitable for normal text
- responsive hero and benchmark layout
- no overlapping text at narrow widths
- command snippets must wrap or scroll cleanly without breaking layout

## Verification Plan

Implementation verification should include:

- static page loads locally
- responsive checks for mobile and desktop widths
- link checks for internal docs paths and external release/GHCR/GitHub URLs
- README status updated
- GitHub Pages workflow syntax validation
- final screenshot/manual visual review

If a build step is introduced, verify the build command locally and document it
in the final implementation summary.

## Open Decisions For Implementation Planning

- Whether to use plain static HTML/CSS or a tiny static-site tool.
- Whether GitHub Pages should publish from `site/` directly or from an Actions
  artifact.
- Exact font pair and color tokens.
- Whether to include a small copy-to-clipboard interaction for commands.
