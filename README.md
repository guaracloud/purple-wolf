# purple-wolf

A fast, low-memory Web Application Firewall delivered as a Traefik plugin.

**Status:** v0.2 in development. [Design spec](docs/superpowers/specs/2026-05-24-purple-wolf-v0.2-design.md).

## What it does

`purple-wolf` inspects every HTTP request reaching a route protected by one
of its Middlewares and either lets it through or returns `403 Forbidden`.
Inspection covers headers, URL, query parameters, and the request body (up
to a configurable cap) using a hybrid engine: libinjection (SQLi/XSS),
aho-corasick literal signatures, structural anomaly checks, and per-IP
rate limiting / deny-listing.

## Quick start (Traefik)

(filled in by Task 25)

## License

Dual-licensed under MIT OR Apache-2.0.
