# Security Policy

## Supported versions

Only the latest released `v0.x` line receives security updates during
the v0.x stream. Older patch versions are not backported.

| Version | Supported |
| ------- | --------- |
| Latest 0.4.x patch | :white_check_mark: |
| 0.3.x and earlier | :x: (superseded) |

## Reporting a vulnerability

**Please do not file a public GitHub issue for a vulnerability.**
Public issues are indexed by scanners and visible to attackers before
maintainers can ship a fix.

Use one of these private channels:

1. **GitHub Security Advisories (preferred):**
   <https://github.com/guaracloud/purple-wolf/security/advisories/new>
   This opens a private draft visible only to repository administrators and
   supports coordinated disclosure and CVE requests.
2. **Email:** **`contact@guaracloud.com`**, with a subject beginning
   `[purple-wolf security]`. This is the contact address published on the
   [Guara Cloud GitHub organization](https://github.com/guaracloud).

The project does not currently publish a PGP key. If an email report contains
sensitive production data, send a high-level description first and ask the
maintainers to arrange an encrypted exchange.

Please include:
- Affected version (`cargo pkgid purple-wolf-core` or the GitHub
  release tag of the `.wasm` you're using).
- A reproduction - ideally a curl command against a local
  `tests/traefik_integration/` stack, or a minimal Rust snippet
  against `purple-wolf-core`.
- The expected vs. observed behavior.
- Any thoughts on severity / blast radius.

## Response SLA

- **Acknowledgement:** within 72 hours.
- **Triage + initial assessment:** within 7 days.
- **Fix + coordinated disclosure timeline:** within 90 days of the
  acknowledgement, as recommended by Google Project Zero. Critical
  vulnerabilities with active exploitation get an expedited path.

If you don't hear back within those windows, follow up through the same private
channel. Please do not switch to a public issue while the report is under
embargo.

## Scope

The scope of "security vulnerability" for this project:

**In scope:**
- Detection bypasses - payloads that REVIEW-class detectors should
  catch per [THREAT_MODEL.md](THREAT_MODEL.md) §2 but don't.
- Memory-safety issues in `crates/purple-wolf-core/src/ffi.rs` and the
  hand-rolled WASM host shim in
  `crates/purple-wolf-traefik/src/host.rs`.
- Self-DoS / amplification primitives reachable from a single HTTP
  request (e.g. uncapped data structures, infinite loops in the
  parser, libinjection inputs that produce O(n²) runtime).
- Audit-log integrity issues (forged log lines via crafted payloads).
- Privilege / sandbox escapes from the wasm guest into Traefik or the
  host process.
- Bypasses of the release pipeline's signing chain (cosign keyless +
  crates.io publish).

**Explicitly out of scope** (per [THREAT_MODEL.md](THREAT_MODEL.md) §3):
- Missing detection for attack classes documented as future work
  (template injection, SSRF, NoSQL, prototype pollution, Log4Shell,
  CRLF/smuggling, stateful pattern detection across requests).
- Vulnerabilities in dependencies that purple-wolf doesn't trigger
  (please report those to the upstream maintainer first).
- Tenant-cluster misconfigurations (e.g. forgetting Traefik's
  `trustedIPs`); these are operational hazards documented in
  [THREAT_MODEL.md](THREAT_MODEL.md) §4.
- Vulnerabilities in Traefik itself; report those to the Traefik
  project.

## Coordinated disclosure

For accepted vulnerabilities we'll:
1. Acknowledge receipt within 72h.
2. Reproduce in a private branch.
3. Draft a fix + a CHANGELOG entry + a CVE request via GitHub Security
   Advisories.
4. Publish the fix in a patch release tagged with the CVE number.
5. Credit the reporter in the changelog (opt-in - say so in your
   report if you'd prefer to remain anonymous).

Embargo period is negotiable case by case; default is "as soon as a
fix ships, but no later than 90 days from acknowledgement".

## Cosign signature verification

Every `purple_wolf_traefik.wasm` release artifact attached to a GitHub Release
is cosign-keyless-signed. To verify before deployment:

```bash
cosign verify-blob \
  --signature purple_wolf_traefik.wasm.sig \
  --certificate purple_wolf_traefik.wasm.pem \
  --certificate-identity-regexp '^https://github\.com/guaracloud/purple-wolf/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  purple_wolf_traefik.wasm
```

The release workflow also runs `cosign verify-blob` against its own
output as a fail-closed gate, so an artifact present on a Release
page necessarily verified at build time - but verifying again at
deployment time is the only way to detect tampering after upload.
