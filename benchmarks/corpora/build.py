"""Build benign + attack JSONL corpora from the existing purple-wolf
test trees for use by the WAF benchmark runner.

Inputs:
  tests/corpus/clean/clean.txt  — hand-curated benign baseline
  tests/corpus/crs/REQUEST-941…  — OWASP CRS XSS regression tests
  tests/corpus/crs/REQUEST-942…  — OWASP CRS SQLi regression tests

Outputs (in benchmarks/corpora/):
  benign.jsonl   — one record per benign request, expected_block=false
  attacks.jsonl  — one record per attack request, expected_block=true

Record shape:
  {"id": "<rule_id>-<test_id>", "class": "xss|sqli|benign",
   "method": "GET|POST|…", "path": "/…", "query": "…",
   "headers": {…}, "body": "…", "expected_block": true|false}

This is the same yardstick the purple-wolf efficacy numbers in
crates/purple-wolf-core/tests/crs_replay.rs measure against. No
goalpost-moving for the benchmark — both WAFs are scored on the
identical corpus.
"""

import json
import re
import sys
import urllib.parse
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "tests/corpus"
OUT = REPO / "benchmarks/corpora"


def split_uri(uri: str) -> tuple[str, str]:
    """`/foo?bar=baz` → (`/foo`, `bar=baz`). URL-encode the query
    component if it isn't already (some CRS samples include literal
    `' OR 1=1` in URI — we keep verbatim so the WAF sees what an
    attacker would actually send)."""
    if "?" in uri:
        path, _, query = uri.partition("?")
    else:
        path, query = uri, ""
    return path or "/", query


def body_to_query(body: str) -> str:
    """CRS POST tests carry the form-encoded payload in `data:`.
    Treat as already form-encoded if it parses cleanly; otherwise
    raw-pass."""
    return body


def extract_crs_class(path: Path, cls: str, attacks: list[dict]) -> None:
    """Walk a REQUEST-XXX-… dir, emit one record per stage."""
    for f in sorted(path.glob("*.yaml")):
        try:
            doc = yaml.safe_load(f.read_text())
        except Exception as e:
            print(f"WARN: {f}: {e}", file=sys.stderr)
            continue
        rule_id = doc.get("rule_id", f.stem)
        for t in doc.get("tests") or []:
            test_id = t.get("test_id", "?")
            for i, st in enumerate(t.get("stages") or []):
                inp = st.get("input") or {}
                method = inp.get("method", "GET").upper()
                uri = inp.get("uri", "/")
                path_q, query = split_uri(uri)
                # Some CRS samples ship a literal "1' OR 1=1" in
                # the URI — leave verbatim so the WAF sees the
                # actual payload an attacker would send.
                headers = dict(inp.get("headers") or {})
                body = inp.get("data", "")
                # Treat anything with stop_magic_format false / no
                # explicit content-type as application/x-www-form-…
                if body and method in {"POST", "PUT", "PATCH"} and \
                        not any(k.lower() == "content-type" for k in headers):
                    headers["Content-Type"] = (
                        "application/x-www-form-urlencoded"
                    )
                attacks.append({
                    "id": f"{rule_id}-{test_id}-{i}",
                    "class": cls,
                    "method": method,
                    "path": path_q,
                    "query": query,
                    "headers": headers,
                    "body": body,
                    "expected_block": True,
                })


def extract_clean(attacks: list[dict]) -> None:
    """`clean.txt` lines are one benign URL each — we GET them with
    a normal browser-like User-Agent."""
    src = CORPUS / "clean/clean.txt"
    if not src.exists():
        print(f"WARN: {src} not found", file=sys.stderr)
        return
    benign_idx = 0
    for raw in src.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Lines look like full URLs (e.g.,
        # "https://example.com/path?q=cats"); strip the
        # scheme/host and keep the path+query so the WAF inspects
        # what an upstream proxy would forward.
        if line.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(line)
            path = parsed.path or "/"
            query = parsed.query
        elif line.startswith("/"):
            path, query = split_uri(line)
        else:
            # JSON body, plain text, or odd shape — POST as body so
            # we still exercise body inspection.
            path, query = "/post", ""
            attacks.append({
                "id": f"benign-{benign_idx}",
                "class": "benign",
                "method": "POST",
                "path": path,
                "query": query,
                "headers": {
                    "Content-Type": "text/plain",
                    "User-Agent": "benchmark-benign/1.0",
                },
                "body": line,
                "expected_block": False,
            })
            benign_idx += 1
            continue
        attacks.append({
            "id": f"benign-{benign_idx}",
            "class": "benign",
            "method": "GET",
            "path": path,
            "query": query,
            "headers": {
                "User-Agent": "Mozilla/5.0 (benchmark-benign)",
            },
            "body": "",
            "expected_block": False,
        })
        benign_idx += 1


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    attacks: list[dict] = []
    extract_crs_class(
        CORPUS / "crs/REQUEST-941-APPLICATION-ATTACK-XSS", "xss", attacks
    )
    extract_crs_class(
        CORPUS / "crs/REQUEST-942-APPLICATION-ATTACK-SQLI", "sqli", attacks
    )
    benign: list[dict] = []
    extract_clean(benign)

    with (OUT / "attacks.jsonl").open("w") as f:
        for r in attacks:
            f.write(json.dumps(r) + "\n")
    with (OUT / "benign.jsonl").open("w") as f:
        for r in benign:
            f.write(json.dumps(r) + "\n")

    print(f"wrote {len(attacks):4d} attacks   → {OUT/'attacks.jsonl'}")
    print(f"wrote {len(benign):4d} benign    → {OUT/'benign.jsonl'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
