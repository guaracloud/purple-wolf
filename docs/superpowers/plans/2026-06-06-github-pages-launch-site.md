# GitHub Pages Launch Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and publish a polished GitHub Pages launch site for Purple Wolf that presents the v0.3 release, benchmark evidence, install paths, and artifact verification story.

**Architecture:** Create an isolated static site under `site/` using plain HTML, CSS, and dependency-free JavaScript. Add a GitHub Pages workflow that uploads `site/` as a static artifact without touching the Rust workspace, Cargo release flow, or runtime examples.

**Tech Stack:** Static HTML5, CSS custom properties, vanilla JavaScript, Node.js standard library for local link checks, GitHub Actions Pages deployment.

---

## File Structure

- Create: `site/index.html`
  - Single-page launch site content, semantic sections, navigation, CTAs, commands, benchmark panels, release links, and footer.
- Create: `site/styles.css`
  - Full visual system: tokens, typography, responsive layout, benchmark panels, request-path diagram, command blocks, accessibility states.
- Create: `site/script.js`
  - Small progressive enhancement for copy-to-clipboard buttons. The site remains useful without JavaScript.
- Create: `site/check-links.mjs`
  - Dependency-free local validation script that checks internal repository links referenced by `site/index.html`.
- Create: `.github/workflows/pages.yml`
  - GitHub Pages deployment workflow for the static `site/` directory.
- Modify: `README.md`
  - Update the status line from v0.3 development wording to v0.3 released wording.
- Optional generated during verification only: local HTTP server process for visual review. Do not commit generated screenshots unless the user asks.

## Implementation Notes

- Do not add `package.json`, npm dependencies, or a framework.
- Do not modify Cargo manifests, release workflow, Dockerfiles, Helm chart, Kustomize overlays, or Rust crates for this site.
- Keep copy factual and bounded. Do not write "enterprise-ready", "military-grade", "blocks everything", or "better than every WAF".
- Use repository-relative links in the static site so GitHub Pages serves them correctly from the project page path.
- Use external links for GitHub release and GHCR package pages.
- Keep `AGENTS.md` untracked and untouched if it is still present.

## Design Tokens To Implement

Use these names in `site/styles.css`:

```css
:root {
  --font-display: "Afacad Flux", "Segoe UI", sans-serif;
  --font-body: "Atkinson Hyperlegible", "Segoe UI", sans-serif;
  --font-code: "Recursive Mono", "SFMono-Regular", Consolas, monospace;

  --ink: oklch(18% 0.025 296);
  --ink-muted: oklch(42% 0.025 296);
  --surface: oklch(98% 0.006 296);
  --surface-raised: oklch(96% 0.012 296);
  --surface-strong: oklch(91% 0.018 296);
  --line: oklch(84% 0.02 296);
  --purple: oklch(45% 0.18 302);
  --purple-soft: oklch(92% 0.045 302);
  --verify: oklch(55% 0.13 166);
  --verify-soft: oklch(92% 0.045 166);
  --warn-soft: oklch(94% 0.035 84);

  --space-2xs: 4px;
  --space-xs: 8px;
  --space-sm: 12px;
  --space-md: 16px;
  --space-lg: 24px;
  --space-xl: 32px;
  --space-2xl: 48px;
  --space-3xl: 64px;
  --space-4xl: 96px;

  --radius-sm: 6px;
  --radius-md: 8px;
  --radius-lg: 14px;
  --shadow-soft: 0 20px 60px oklch(18% 0.025 296 / 0.08);
}
```

Font import guidance:

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Afacad+Flux:wght@500;600;700&family=Atkinson+Hyperlegible:ital,wght@0,400;0,700;1,400&family=Recursive+Mono:wght@500;600&display=swap" rel="stylesheet">
```

These fonts avoid the common default choices banned by the impeccable guidance while keeping the page readable. The implementation should use system fallbacks if Google Fonts fail.

---

### Task 1: Static Site Skeleton And Core Content

**Files:**
- Create: `site/index.html`

- [ ] **Step 1: Create the semantic HTML shell**

Add `site/index.html` with this structure and content. Keep the IDs exactly as shown because later tasks style and link against them.

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="Purple Wolf is a fast, verifiable Web Application Firewall for Traefik, shipped as a WASM plugin with signed releases, SBOMs, Helm, and Kustomize packaging.">
    <meta property="og:title" content="Purple Wolf - A fast, verifiable WAF for Traefik">
    <meta property="og:description" content="Traefik WASM WAF with signed artifacts, SBOMs, benchmark evidence, and monitor-first Kubernetes rollout.">
    <meta property="og:type" content="website">
    <title>Purple Wolf - A fast, verifiable WAF for Traefik</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Afacad+Flux:wght@500;600;700&family=Atkinson+Hyperlegible:ital,wght@0,400;0,700;1,400&family=Recursive+Mono:wght@500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="./styles.css">
  </head>
  <body>
    <a class="skip-link" href="#main">Skip to content</a>
    <header class="site-header">
      <nav class="nav" aria-label="Primary navigation">
        <a class="brand" href="./index.html" aria-label="Purple Wolf home">
          <span class="brand-mark" aria-hidden="true">PW</span>
          <span>Purple Wolf</span>
        </a>
        <div class="nav-links">
          <a href="#benchmark">Benchmark</a>
          <a href="#install">Install</a>
          <a href="#verify">Verify</a>
          <a href="https://github.com/guaracloud/purple-wolf">GitHub</a>
        </div>
      </nav>
    </header>

    <main id="main">
      <section class="hero section">
        <div class="hero-copy">
          <p class="eyebrow">Traefik WASM WAF · v0.3 released</p>
          <h1>A fast, verifiable WAF for Traefik.</h1>
          <p class="hero-lede">
            Purple Wolf runs as a Traefik WASM plugin, ships signed release
            artifacts, publishes SBOMs and digest-pinned images, and supports a
            monitor-first Kubernetes rollout through Helm and Kustomize.
          </p>
          <div class="hero-actions" aria-label="Primary actions">
            <a class="button button-primary" href="#demo">Try the demo</a>
            <a class="button button-secondary" href="https://github.com/guaracloud/purple-wolf/releases/tag/v0.3.0">View v0.3 release</a>
            <a class="button button-ghost" href="#helm">Install with Helm</a>
          </div>
          <ul class="trust-row" aria-label="Release and deployment properties">
            <li>Traefik WASM plugin</li>
            <li>Signed artifacts</li>
            <li>SPDX SBOMs</li>
            <li>Helm OCI chart</li>
            <li>Monitor-first rollout</li>
          </ul>
        </div>

        <div class="request-map" aria-label="Request path through Purple Wolf">
          <p class="map-label">request path</p>
          <div class="map-row">
            <div class="map-node">Traefik</div>
            <div class="map-arrow" aria-hidden="true">-></div>
            <div class="map-node map-node-strong">Purple Wolf WASM</div>
            <div class="map-arrow" aria-hidden="true">-></div>
            <div class="map-node">Backend</div>
          </div>
          <div class="map-branch" aria-hidden="true">|</div>
          <div class="map-node map-node-relay">Relay / SIEM</div>
          <p class="map-note">Inspect inline. Deliver signed audit events out of band.</p>
        </div>
      </section>

      <section class="audiences section" aria-labelledby="audiences-title">
        <div class="section-heading">
          <p class="eyebrow">Built for rollout, not shelfware</p>
          <h2 id="audiences-title">Three teams, one request path.</h2>
        </div>
        <div class="audience-grid">
          <article class="audience audience-security">
            <h3>Security engineers</h3>
            <p>Threat boundaries, signed releases, SBOMs, and HMAC-signed relay events for SIEM or tenant webhook delivery.</p>
            <a href="../THREAT_MODEL.md">Read the threat model</a>
          </article>
          <article class="audience audience-platform">
            <h3>DevOps and Kubernetes operators</h3>
            <p>Helm, Kustomize, hardened container defaults, digest-pinned images, and monitor-first rollout guidance.</p>
            <a href="../docs/kubernetes-production.md">Open production notes</a>
          </article>
          <article class="audience audience-traefik">
            <h3>Traefik users</h3>
            <p>A WASM plugin that fits Traefik Middleware workflows, with a local demo and monitor/enforce examples.</p>
            <a href="../examples/demo/README.md">Run the local demo</a>
          </article>
        </div>
      </section>

      <section id="benchmark" class="benchmark section" aria-labelledby="benchmark-title">
        <div class="section-heading">
          <p class="eyebrow">Benchmark snapshot</p>
          <h2 id="benchmark-title">Low overhead, bounded claims.</h2>
          <p>
            Same Traefik http-wasm shape, same resource budget, same yardstick.
            This is not a claim that Purple Wolf is better than every Coraza
            deployment or every WAF mode.
          </p>
        </div>
        <div class="metric-layout">
          <article class="metric metric-primary">
            <span class="metric-value">+0.1-0.2 ms</span>
            <span class="metric-label">isolated p99 WAF overhead</span>
          </article>
          <article class="metric">
            <span class="metric-value">~8,000 RPS</span>
            <span class="metric-label">sustained under tested resources</span>
          </article>
          <article class="metric">
            <span class="metric-value">80-96 MiB</span>
            <span class="metric-label">memory band during soak</span>
          </article>
          <article class="metric comparison">
            <span class="metric-value">14.55% vs 6.11%</span>
            <span class="metric-label">detection in same-shape http-wasm comparison</span>
          </article>
        </div>
        <a class="text-link" href="../docs/benchmark.md">Read the full methodology and caveats</a>
      </section>

      <section class="workflow section" aria-labelledby="workflow-title">
        <div class="section-heading">
          <p class="eyebrow">How it works</p>
          <h2 id="workflow-title">Inline inspection, out-of-band audit delivery.</h2>
        </div>
        <div class="workflow-grid">
          <div class="workflow-step">
            <span>01</span>
            <h3>Traefik receives the request</h3>
            <p>Attach Purple Wolf Middleware to selected routes without changing your backend service.</p>
          </div>
          <div class="workflow-step">
            <span>02</span>
            <h3>The WASM plugin inspects</h3>
            <p>Headers, URL, query parameters, and capped request bodies are evaluated in the request path.</p>
          </div>
          <div class="workflow-step">
            <span>03</span>
            <h3>The relay fans out audit events</h3>
            <p>Run the relay when signed webhook delivery to SIEM, Slack bridges, or tenant subscribers is needed.</p>
          </div>
        </div>
      </section>

      <section id="install" class="install section" aria-labelledby="install-title">
        <div class="section-heading">
          <p class="eyebrow">Install paths</p>
          <h2 id="install-title">Try locally, then roll out deliberately.</h2>
        </div>
        <div class="command-stack">
          <article id="demo" class="command-card">
            <div>
              <h3>Local demo</h3>
              <p>Traefik, Purple Wolf WASM, backend echo service, relay, and HMAC-verifying subscriber.</p>
            </div>
            <pre><code>docker compose -f examples/demo/docker-compose.yml up --build</code></pre>
          </article>
          <article id="helm" class="command-card">
            <div>
              <h3>Helm OCI chart</h3>
              <p>Install monitor-mode examples without attaching them to production routes automatically.</p>
            </div>
            <pre><code>helm install purple-wolf oci://ghcr.io/guaracloud/charts/purple-wolf \
  --version 0.3.0 \
  -f charts/purple-wolf/values.monitor.yaml</code></pre>
          </article>
          <article class="command-card">
            <div>
              <h3>Kustomize</h3>
              <p>Start from the monitor-mode overlay and attach Middleware route by route.</p>
            </div>
            <pre><code>kubectl apply -k deploy/kubernetes/overlays/monitor-mode</code></pre>
          </article>
        </div>
      </section>

      <section id="verify" class="verify section" aria-labelledby="verify-title">
        <div class="section-heading">
          <p class="eyebrow">Verify before production</p>
          <h2 id="verify-title">Install by digest, not by hope.</h2>
          <p>Every public release includes a manifest, signatures, checksums, SBOMs, image digests, and the Helm chart digest.</p>
        </div>
        <div class="verify-list" aria-label="Release verification checklist">
          <span>release-manifest.json</span>
          <span>Cosign signatures</span>
          <span>SPDX SBOMs</span>
          <span>GHCR image digests</span>
          <span>Helm OCI digest</span>
        </div>
        <a class="button button-secondary" href="../docs/release-verification.md">Open verification guide</a>
      </section>

      <section class="rollout section" aria-labelledby="rollout-title">
        <div class="section-heading">
          <p class="eyebrow">Rollout model</p>
          <h2 id="rollout-title">Monitor first. Enforce deliberately.</h2>
        </div>
        <ol class="rollout-list">
          <li>Install monitor-mode examples.</li>
          <li>Attach <code>purple-wolf-monitor</code> to selected routes.</li>
          <li>Inspect audit events and webhook output.</li>
          <li>Tune policy and body limits.</li>
          <li>Opt into enforce mode route by route.</li>
        </ol>
      </section>
    </main>

    <footer class="site-footer">
      <div>
        <strong>Purple Wolf</strong>
        <p>Dual-licensed under MIT OR Apache-2.0.</p>
      </div>
      <nav aria-label="Footer links">
        <a href="https://github.com/guaracloud/purple-wolf">GitHub</a>
        <a href="https://github.com/guaracloud/purple-wolf/releases/tag/v0.3.0">v0.3.0 release</a>
        <a href="../docs/configuration.md">Configuration</a>
        <a href="../docs/benchmark.md">Benchmark</a>
        <a href="../THREAT_MODEL.md">Threat model</a>
      </nav>
    </footer>
    <script src="./script.js" defer></script>
  </body>
</html>
```

- [ ] **Step 2: Run a basic static file check**

Run:

```bash
test -f site/index.html && grep -q "A fast, verifiable WAF for Traefik" site/index.html
```

Expected: command exits with status 0 and prints no output.

- [ ] **Step 3: Commit the skeleton**

```bash
git add site/index.html
git commit -m "docs: add launch site content"
```

---

### Task 2: Visual System And Responsive Layout

**Files:**
- Create: `site/styles.css`

- [ ] **Step 1: Create the CSS foundation**

Add `site/styles.css` with the token block from this plan and these global rules:

```css
* {
  box-sizing: border-box;
}

html {
  scroll-behavior: smooth;
}

body {
  margin: 0;
  min-width: 320px;
  color: var(--ink);
  background:
    linear-gradient(180deg, oklch(98% 0.006 296), oklch(95% 0.012 296) 52%, oklch(98% 0.006 296));
  font-family: var(--font-body);
  font-size: 1rem;
  line-height: 1.6;
}

a {
  color: inherit;
  text-decoration-color: color-mix(in oklch, var(--purple), transparent 45%);
  text-underline-offset: 0.18em;
}

a:hover {
  text-decoration-color: var(--purple);
}

.skip-link {
  position: fixed;
  left: var(--space-md);
  top: var(--space-md);
  z-index: 20;
  transform: translateY(-160%);
  padding: var(--space-sm) var(--space-md);
  border-radius: var(--radius-sm);
  background: var(--ink);
  color: var(--surface);
}

.skip-link:focus {
  transform: translateY(0);
}

.section {
  width: min(1180px, calc(100% - 32px));
  margin-inline: auto;
  padding-block: clamp(48px, 8vw, 96px);
}

.section-heading {
  max-width: 760px;
}

.eyebrow {
  margin: 0 0 var(--space-sm);
  color: var(--purple);
  font-weight: 700;
  letter-spacing: 0;
  text-transform: none;
}

h1,
h2,
h3 {
  margin: 0;
  font-family: var(--font-display);
  line-height: 0.98;
  letter-spacing: 0;
}

h1 {
  max-width: 850px;
  font-size: clamp(3.5rem, 8vw, 7.5rem);
}

h2 {
  font-size: clamp(2.25rem, 5vw, 4.75rem);
}

h3 {
  font-size: clamp(1.35rem, 2.4vw, 2rem);
}

p {
  max-width: 72ch;
}
```

- [ ] **Step 2: Add layout and component CSS**

Continue `site/styles.css` with focused section styling:

```css
.site-header {
  position: sticky;
  top: 0;
  z-index: 10;
  border-bottom: 1px solid color-mix(in oklch, var(--line), transparent 45%);
  background: color-mix(in oklch, var(--surface), transparent 8%);
  backdrop-filter: blur(16px);
}

.nav {
  width: min(1180px, calc(100% - 32px));
  margin-inline: auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-lg);
  padding-block: var(--space-md);
}

.brand,
.nav-links,
.hero-actions,
.trust-row,
.verify-list {
  display: flex;
  align-items: center;
  gap: var(--space-sm);
  flex-wrap: wrap;
}

.brand {
  font-weight: 700;
  text-decoration: none;
}

.brand-mark {
  display: inline-grid;
  place-items: center;
  width: 34px;
  aspect-ratio: 1;
  border-radius: var(--radius-sm);
  background: var(--ink);
  color: var(--surface);
  font-family: var(--font-display);
}

.nav-links a {
  color: var(--ink-muted);
  font-size: 0.95rem;
  text-decoration: none;
}

.hero {
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(320px, 0.75fr);
  align-items: center;
  gap: clamp(32px, 6vw, 80px);
  min-height: calc(100svh - 72px);
}

.hero-lede {
  margin-block: var(--space-lg);
  color: var(--ink-muted);
  font-size: clamp(1.1rem, 2vw, 1.35rem);
}

.button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  padding: 0 var(--space-lg);
  border: 1px solid var(--line);
  border-radius: var(--radius-md);
  font-weight: 700;
  text-decoration: none;
}

.button-primary {
  border-color: var(--ink);
  background: var(--ink);
  color: var(--surface);
}

.button-secondary {
  border-color: color-mix(in oklch, var(--purple), var(--line) 35%);
  background: var(--purple-soft);
  color: var(--purple);
}

.button-ghost {
  background: color-mix(in oklch, var(--surface), transparent 15%);
}

.trust-row {
  margin: var(--space-xl) 0 0;
  padding: 0;
  list-style: none;
}

.trust-row li,
.verify-list span {
  border: 1px solid var(--line);
  border-radius: 999px;
  padding: var(--space-xs) var(--space-sm);
  background: color-mix(in oklch, var(--surface), transparent 10%);
  color: var(--ink-muted);
  font-size: 0.94rem;
}

.request-map {
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  padding: var(--space-xl);
  background: var(--surface-raised);
  box-shadow: var(--shadow-soft);
}

.map-label,
.map-note {
  margin: 0;
  color: var(--ink-muted);
}

.map-row {
  display: grid;
  grid-template-columns: 1fr auto 1.25fr auto 1fr;
  align-items: center;
  gap: var(--space-sm);
  margin-block: var(--space-lg);
}

.map-node {
  display: grid;
  min-height: 74px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: var(--radius-md);
  background: var(--surface);
  text-align: center;
  font-weight: 700;
}

.map-node-strong {
  border-color: color-mix(in oklch, var(--purple), var(--line) 35%);
  background: var(--purple-soft);
  color: var(--purple);
}

.map-node-relay {
  width: min(260px, 100%);
  margin-inline: auto;
  background: var(--verify-soft);
}

.map-arrow,
.map-branch {
  color: var(--ink-muted);
  font-family: var(--font-code);
  text-align: center;
}

.audience-grid,
.metric-layout,
.workflow-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--space-lg);
  margin-top: var(--space-xl);
}

.audience,
.metric,
.workflow-step,
.command-card {
  border: 1px solid var(--line);
  border-radius: var(--radius-lg);
  background: color-mix(in oklch, var(--surface), transparent 8%);
  padding: var(--space-lg);
}

.audience p,
.workflow-step p,
.command-card p {
  color: var(--ink-muted);
}

.metric-layout {
  grid-template-columns: 1.35fr 1fr 1fr;
}

.metric-primary {
  grid-row: span 2;
}

.comparison {
  grid-column: span 2;
}

.metric-value {
  display: block;
  font-family: var(--font-display);
  font-size: clamp(2.2rem, 5vw, 5rem);
  font-weight: 700;
  line-height: 0.95;
}

.metric-label {
  display: block;
  margin-top: var(--space-sm);
  color: var(--ink-muted);
}

.workflow-step span {
  display: inline-grid;
  place-items: center;
  width: 38px;
  aspect-ratio: 1;
  border-radius: 999px;
  background: var(--surface-strong);
  color: var(--purple);
  font-weight: 700;
}

.command-stack {
  display: grid;
  gap: var(--space-lg);
  margin-top: var(--space-xl);
}

.command-card {
  display: grid;
  grid-template-columns: minmax(220px, 0.8fr) minmax(0, 1.2fr);
  gap: var(--space-lg);
  align-items: center;
}

pre {
  overflow-x: auto;
  margin: 0;
  border-radius: var(--radius-md);
  background: var(--ink);
  color: var(--surface);
  padding: var(--space-lg);
  font-family: var(--font-code);
  font-size: 0.94rem;
  line-height: 1.55;
}

code {
  font-family: var(--font-code);
}

.rollout-list {
  display: grid;
  gap: var(--space-sm);
  max-width: 760px;
  padding-left: 1.4rem;
  color: var(--ink-muted);
}

.site-footer {
  width: min(1180px, calc(100% - 32px));
  margin-inline: auto;
  display: flex;
  justify-content: space-between;
  gap: var(--space-lg);
  border-top: 1px solid var(--line);
  padding-block: var(--space-xl);
}

.site-footer nav {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-sm);
}
```

- [ ] **Step 3: Add responsive rules**

Append this responsive CSS:

```css
@media (max-width: 900px) {
  .hero,
  .command-card {
    grid-template-columns: 1fr;
  }

  .hero {
    min-height: auto;
  }

  .audience-grid,
  .metric-layout,
  .workflow-grid {
    grid-template-columns: 1fr;
  }

  .metric-primary,
  .comparison {
    grid-row: auto;
    grid-column: auto;
  }

  .map-row {
    grid-template-columns: 1fr;
  }

  .map-arrow {
    transform: rotate(90deg);
  }

  .site-footer {
    flex-direction: column;
  }
}

@media (max-width: 640px) {
  .nav {
    align-items: flex-start;
    flex-direction: column;
  }

  h1 {
    font-size: clamp(3rem, 18vw, 4.5rem);
  }

  .section {
    width: min(100% - 24px, 1180px);
  }

  .request-map,
  .audience,
  .metric,
  .workflow-step,
  .command-card {
    padding: var(--space-md);
  }
}

@media (prefers-reduced-motion: reduce) {
  html {
    scroll-behavior: auto;
  }
}
```

- [ ] **Step 4: Run CSS smoke checks**

Run:

```bash
test -f site/styles.css
grep -q "oklch" site/styles.css
grep -q "@media (max-width: 900px)" site/styles.css
grep -q "@media (max-width: 640px)" site/styles.css
! grep -q "background-clip: text" site/styles.css
```

Expected: all commands exit with status 0.

- [ ] **Step 5: Commit the visual system**

```bash
git add site/styles.css
git commit -m "docs: style purple wolf launch site"
```

---

### Task 3: Copy Buttons And Local Link Checker

**Files:**
- Create: `site/script.js`
- Create: `site/check-links.mjs`
- Modify: `site/index.html`

- [ ] **Step 1: Add copy button containers to command cards**

In `site/index.html`, wrap each `<pre><code>...</code></pre>` command in a `.command-code` container and add a button.

For each command card, use this shape:

```html
<div class="command-code">
  <button class="copy-button" type="button">Copy</button>
  <pre><code>docker compose -f examples/demo/docker-compose.yml up --build</code></pre>
</div>
```

The Helm command block should preserve line continuations. The Kustomize command block should use the same `.command-code` wrapper.

- [ ] **Step 2: Add copy button CSS**

Append to `site/styles.css`:

```css
.command-code {
  position: relative;
  min-width: 0;
}

.copy-button {
  position: absolute;
  right: var(--space-sm);
  top: var(--space-sm);
  min-height: 34px;
  border: 1px solid color-mix(in oklch, var(--surface), transparent 55%);
  border-radius: var(--radius-sm);
  background: color-mix(in oklch, var(--surface), transparent 10%);
  color: var(--ink);
  font: 700 0.85rem var(--font-body);
  cursor: pointer;
}

.copy-button:focus-visible,
.button:focus-visible,
a:focus-visible {
  outline: 3px solid color-mix(in oklch, var(--purple), white 35%);
  outline-offset: 3px;
}
```

- [ ] **Step 3: Create the copy script**

Add `site/script.js`:

```js
const copyButtons = document.querySelectorAll(".copy-button");

copyButtons.forEach((button) => {
  button.addEventListener("click", async () => {
    const code = button.parentElement?.querySelector("code")?.textContent;
    if (!code) return;

    try {
      await navigator.clipboard.writeText(code);
      button.textContent = "Copied";
      window.setTimeout(() => {
        button.textContent = "Copy";
      }, 1600);
    } catch {
      button.textContent = "Select";
      window.setTimeout(() => {
        button.textContent = "Copy";
      }, 1600);
    }
  });
});
```

- [ ] **Step 4: Create the local link checker**

Add `site/check-links.mjs`:

```js
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const htmlPath = resolve(root, "site/index.html");
const html = readFileSync(htmlPath, "utf8");
const linkPattern = /\b(?:href|src)="([^"]+)"/g;
const failures = [];

for (const match of html.matchAll(linkPattern)) {
  const target = match[1];

  if (
    target.startsWith("#") ||
    target.startsWith("http://") ||
    target.startsWith("https://") ||
    target.startsWith("mailto:")
  ) {
    continue;
  }

  const cleanTarget = target.split("#")[0].split("?")[0];
  const absoluteTarget = resolve(root, "site", cleanTarget);

  if (!existsSync(absoluteTarget)) {
    failures.push(target);
  }
}

if (failures.length > 0) {
  console.error("Broken local links:");
  for (const failure of failures) {
    console.error(`- ${failure}`);
  }
  process.exit(1);
}

console.log("Local links ok");
```

- [ ] **Step 5: Run link and script checks**

Run:

```bash
node --check site/script.js
node site/check-links.mjs
```

Expected:

```text
Local links ok
```

- [ ] **Step 6: Commit interactions and link checker**

```bash
git add site/index.html site/styles.css site/script.js site/check-links.mjs
git commit -m "docs: add launch site command interactions"
```

---

### Task 4: README Status Update

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace the status paragraph**

Change the top status paragraph to:

```markdown
**Status:** v0.3 released (audit labels, webhook relay, signed release
artifacts, SBOMs, Helm OCI chart, and Kubernetes packaging). See
[THREAT_MODEL.md](THREAT_MODEL.md) for what the WAF is and is not designed
to catch, and [docs/configuration.md](docs/configuration.md) for the
Middleware config reference. The webhook protocol contract lives in
[docs/webhook-protocol.md](docs/webhook-protocol.md).
```

- [ ] **Step 2: Verify the old wording is gone**

Run:

```bash
grep -q "v0.3 released" README.md
! grep -q "v0.3 in development" README.md
```

Expected: both commands exit with status 0.

- [ ] **Step 3: Commit README status**

```bash
git add README.md
git commit -m "docs: mark v0.3 as released"
```

---

### Task 5: GitHub Pages Workflow

**Files:**
- Create: `.github/workflows/pages.yml`

- [ ] **Step 1: Add the Pages workflow**

Create `.github/workflows/pages.yml`:

```yaml
name: pages

on:
  push:
    branches: ["main"]
    paths:
      - "site/**"
      - ".github/workflows/pages.yml"
  workflow_dispatch:

concurrency:
  group: pages
  cancel-in-progress: true

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - uses: actions/checkout@v4

      - uses: actions/configure-pages@v5

      - uses: actions/upload-pages-artifact@v3
        with:
          path: site

      - id: deployment
        uses: actions/deploy-pages@v4
```

- [ ] **Step 2: Validate workflow YAML and action syntax**

Run:

```bash
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/pages.yml"); puts "pages yaml ok"'
go run github.com/rhysd/actionlint/cmd/actionlint@latest .github/workflows/pages.yml
```

Expected:

```text
pages yaml ok
```

`actionlint` exits with status 0.

- [ ] **Step 3: Commit Pages workflow**

```bash
git add .github/workflows/pages.yml
git commit -m "ci: publish launch site to github pages"
```

---

### Task 6: Local Visual Verification

**Files:**
- Read: `site/index.html`
- Read: `site/styles.css`
- Read: `site/script.js`

- [ ] **Step 1: Start a local static server**

Run:

```bash
python3 -m http.server 4173 --directory site
```

Expected: server listens at `http://localhost:4173`.

- [ ] **Step 2: Open the page in a browser**

Use the Browser plugin or an equivalent local browser tool to open:

```text
http://localhost:4173
```

Check desktop viewport first:

- hero text is visible in first viewport
- request-path diagram is visible and not cramped
- benchmark metrics are readable
- buttons have clear hierarchy
- no text overlaps
- no command block escapes its container

- [ ] **Step 3: Check mobile viewport**

Set a mobile-width viewport around 390 px wide and verify:

- navigation wraps cleanly
- hero headline fits without clipping
- request-path diagram stacks vertically
- command blocks scroll horizontally if needed
- copy buttons do not cover essential command text
- sections remain visually distinct without nested-card noise

- [ ] **Step 4: Stop the local static server**

Stop the `python3 -m http.server` process before finalizing the task.

- [ ] **Step 5: Fix visual issues if found**

If the browser check shows overlap, unreadable contrast, clipped text, or broken responsive layout, patch only `site/index.html`, `site/styles.css`, or `site/script.js`, then rerun:

```bash
node --check site/script.js
node site/check-links.mjs
```

Commit any visual fixes:

```bash
git add site/index.html site/styles.css site/script.js
git commit -m "docs: polish launch site layout"
```

If no visual issues are found, do not create an empty commit.

---

### Task 7: Final Verification And Push Readiness

**Files:**
- Read: all changed files

- [ ] **Step 1: Run final local verification**

Run:

```bash
node --check site/script.js
node site/check-links.mjs
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/pages.yml"); puts "pages yaml ok"'
go run github.com/rhysd/actionlint/cmd/actionlint@latest .github/workflows/pages.yml
git diff --check
```

Expected:

```text
Local links ok
pages yaml ok
```

All commands exit with status 0.

- [ ] **Step 2: Confirm README status**

Run:

```bash
grep -n "Status:" README.md
```

Expected output includes:

```text
v0.3 released
```

- [ ] **Step 3: Review final file list**

Run:

```bash
git status --short --branch
```

Expected: only intentional committed changes are ahead of `origin/main`; `AGENTS.md` may still appear untracked and should remain untouched.

- [ ] **Step 4: Push only after user approval**

Ask the user before pushing the implementation branch. If approved and SSH still fails, use the existing HTTPS fallback pattern:

```bash
orig_url=$(git remote get-url origin)
gh auth setup-git >/dev/null 2>&1 || true
git remote set-url origin https://github.com/guaracloud/purple-wolf.git
git push origin main
git remote set-url origin "$orig_url"
```

- [ ] **Step 5: Verify GitHub Pages deployment**

After push, check the `pages` workflow:

```bash
gh run list --repo guaracloud/purple-wolf --workflow pages.yml --limit 3
```

If a run exists, watch it:

```bash
gh run watch <run-id> --repo guaracloud/purple-wolf --exit-status
```

Expected: workflow completes successfully and reports a GitHub Pages URL.

---

## Self-Review

- Spec coverage: The plan covers the hero, audience paths, benchmark snapshot, request-path explanation, install paths, release verification, monitor-to-enforce rollout, footer links, README status update, accessibility, responsiveness, and GitHub Pages deployment.
- Scope: This is one coherent static-site implementation. It does not require splitting into separate sub-projects.
- Placeholders: The plan contains concrete files, commands, expected outputs, and copy. It does not use deferred implementation placeholders.
- Type and naming consistency: HTML IDs used by navigation and sections are defined in Task 1; CSS classes referenced by later tasks are introduced before use or in the same task.
