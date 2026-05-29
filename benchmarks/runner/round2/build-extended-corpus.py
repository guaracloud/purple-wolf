"""Build the extended attacks JSONL corpus used by round 2 of the
WAF benchmark.

Reads:
  benchmarks/corpora/crs/REQUEST-913-…   (Scanner)
  benchmarks/corpora/crs/REQUEST-920-…   (Protocol Enforcement)
  benchmarks/corpora/crs/REQUEST-921-…   (Protocol Attack)
  benchmarks/corpora/crs/REQUEST-930-…   (LFI)
  benchmarks/corpora/crs/REQUEST-931-…   (RFI)
  benchmarks/corpora/crs/REQUEST-932-…   (RCE)
  benchmarks/corpora/crs/REQUEST-933-…   (PHP)
  benchmarks/corpora/crs/REQUEST-934-…   (Generic)
  tests/corpus/crs/REQUEST-941-…         (XSS)
  tests/corpus/crs/REQUEST-942-…         (SQLi)
  benchmarks/corpora/crs/REQUEST-943-…   (Session Fixation)
  benchmarks/corpora/crs/REQUEST-944-…   (Java)

Writes one JSON object per line to the specified output file. Each
record looks like:

  {"id": "942100-1-0", "class": "sqli",
   "method": "POST", "path": "/post", "query": "",
   "headers": {"Content-Type": "application/x-www-form-urlencoded", …},
   "body": "var=1234 OR 1=1", "expected_block": true}

Usage:
  python build-extended-corpus.py \\
      --out benchmarks/results/round2-<ts>/attacks-extended.jsonl
"""

import argparse
import glob
import json
import os
import sys
from pathlib import Path

try:
    import yaml  # type: ignore
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")


REPO = Path(__file__).resolve().parents[3]

CASES = [
    ("benchmarks/corpora/crs/REQUEST-913-SCANNER-DETECTION", "scanner"),
    ("benchmarks/corpora/crs/REQUEST-920-PROTOCOL-ENFORCEMENT", "protocol_enforcement"),
    ("benchmarks/corpora/crs/REQUEST-921-PROTOCOL-ATTACK", "protocol_attack"),
    ("benchmarks/corpora/crs/REQUEST-930-APPLICATION-ATTACK-LFI", "lfi"),
    ("benchmarks/corpora/crs/REQUEST-931-APPLICATION-ATTACK-RFI", "rfi"),
    ("benchmarks/corpora/crs/REQUEST-932-APPLICATION-ATTACK-RCE", "rce"),
    ("benchmarks/corpora/crs/REQUEST-933-APPLICATION-ATTACK-PHP", "php"),
    ("benchmarks/corpora/crs/REQUEST-934-APPLICATION-ATTACK-GENERIC", "generic"),
    ("tests/corpus/crs/REQUEST-941-APPLICATION-ATTACK-XSS", "xss"),
    ("tests/corpus/crs/REQUEST-942-APPLICATION-ATTACK-SQLI", "sqli"),
    ("benchmarks/corpora/crs/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION", "session_fixation"),
    ("benchmarks/corpora/crs/REQUEST-944-APPLICATION-ATTACK-JAVA", "java"),
]


def split_uri(uri: str) -> tuple[str, str]:
    if not uri:
        return "/", ""
    if "?" in uri:
        path, _, query = uri.partition("?")
        return path or "/", query
    return uri, ""


def extract(dir_path: Path, cls: str, out: list[dict]) -> int:
    """Walk one REQUEST-XXX-* directory; append records to `out`.
    Robust against malformed/empty CRS test stages."""
    n0 = len(out)
    for f in sorted(glob.glob(str(dir_path / "*.yaml"))):
        try:
            doc = yaml.safe_load(open(f).read())
        except Exception as e:
            print(f"WARN: {f}: {e}", file=sys.stderr)
            continue
        if not isinstance(doc, dict):
            continue
        rid = doc.get("rule_id", Path(f).stem)
        for t in doc.get("tests") or []:
            if not isinstance(t, dict):
                continue
            tid = t.get("test_id", "?")
            for i, st in enumerate(t.get("stages") or []):
                if not isinstance(st, dict):
                    continue
                inp = st.get("input") or {}
                if not isinstance(inp, dict):
                    continue
                method = (inp.get("method") or "GET").upper()
                uri = inp.get("uri") or "/"
                path, query = split_uri(uri)
                hdrs_raw = inp.get("headers") or {}
                hdrs = dict(hdrs_raw) if isinstance(hdrs_raw, dict) else {}
                body = inp.get("data")
                if isinstance(body, list):
                    body = "&".join(str(x) for x in body)
                body = body or ""
                if (
                    body
                    and method in {"POST", "PUT", "PATCH"}
                    and not any(k.lower() == "content-type" for k in hdrs)
                ):
                    hdrs["Content-Type"] = "application/x-www-form-urlencoded"
                out.append({
                    "id": f"{rid}-{tid}-{i}",
                    "class": cls,
                    "method": method,
                    "path": path,
                    "query": query,
                    "headers": hdrs,
                    "body": body,
                    "expected_block": True,
                })
    return len(out) - n0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="output JSONL path")
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    attacks: list[dict] = []
    for rel, cls in CASES:
        d = REPO / rel
        if not d.exists():
            print(f"WARN: missing dir {d}", file=sys.stderr)
            continue
        added = extract(d, cls, attacks)
        print(f"  {cls:22s} +{added:4d}")

    with out_path.open("w") as f:
        for rec in attacks:
            f.write(json.dumps(rec) + "\n")
    print(f"wrote {len(attacks)} attacks → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
