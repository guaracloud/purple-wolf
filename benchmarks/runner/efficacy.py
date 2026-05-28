"""WAF efficacy runner.

Reads the attacks + benign JSONL corpora, sends each request to the
target (a Service URL inside the cluster), records the observed HTTP
status code, and emits a per-(target, class) aggregate plus the raw
per-request results.

A 403 from the target counts as "blocked". 5xx is recorded but not
counted as a block — that's a WAF *crash*, not a *deny*. 4xx other
than 403 (e.g. 400 from a body the WAF couldn't parse) is recorded
as "other".

Usage:
  python efficacy.py \\
    --target http://bench-pw:8080 \\
    --label purple-wolf \\
    --attacks /corpus/attacks.jsonl \\
    --benign  /corpus/benign.jsonl \\
    --concurrency 8 \\
    --out-summary  /out/efficacy-summary.jsonl \\
    --out-raw      /out/efficacy-raw.jsonl
"""

import argparse
import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path

import httpx


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True, help="base URL, no trailing /")
    p.add_argument("--label", required=True)
    p.add_argument("--attacks", required=True)
    p.add_argument("--benign", required=True)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--out-summary", required=True)
    p.add_argument("--out-raw", required=True)
    p.add_argument("--per-request-timeout", type=float, default=5.0)
    p.add_argument(
        "--max-requests",
        type=int,
        default=0,
        help="optional cap for smoke tests; 0 = no cap",
    )
    return p.parse_args()


def _safe_headers(h: dict) -> dict:
    """Strip non-ASCII from header values — httpx defaults to ASCII
    and CRS test data ships UTF-8 in some samples (e.g., fullwidth
    `<`). For the WAF the original byte payload would arrive in the
    URI/body anyway, not the headers; we just need *something* that
    serializes."""
    out = {}
    for k, v in (h or {}).items():
        try:
            v.encode("ascii")
            out[str(k)] = str(v)
        except UnicodeEncodeError:
            out[str(k)] = v.encode("ascii", "replace").decode("ascii")
    return out


async def one_request(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    target: str,
    rec: dict,
    timeout: float,
) -> dict:
    """Send one corpus record; return a result dict."""
    method = rec["method"].upper()
    path = rec["path"]
    query = rec["query"]
    headers = _safe_headers(rec["headers"])
    body = rec.get("body") or ""
    url = target + path
    if query:
        url = f"{url}?{query}"
    async with sem:
        t0 = time.perf_counter()
        try:
            r = await client.request(
                method,
                url,
                headers=headers,
                content=body if body else None,
                timeout=timeout,
            )
            status = r.status_code
            err = ""
        except (
            httpx.TimeoutException,
            httpx.ConnectError,
            httpx.HTTPError,
        ) as e:
            status = 0
            err = type(e).__name__
        ms = (time.perf_counter() - t0) * 1000.0
    return {
        "id": rec["id"],
        "class": rec["class"],
        "expected_block": rec["expected_block"],
        "status": status,
        "elapsed_ms": round(ms, 2),
        "error": err,
    }


async def run_all_streaming(
    target: str,
    records: list[dict],
    concurrency: int,
    timeout: float,
    raw_path: str,
    label: str,
) -> list[dict]:
    """Drive the corpus concurrently, streaming raw results to disk
    so we never hold the full set in memory (previous version OOM'd
    at 512Mi when many requests timed out)."""
    limits = httpx.Limits(
        max_connections=concurrency * 2,
        max_keepalive_connections=concurrency,
    )
    sem = asyncio.Semaphore(concurrency)
    summary_records: list[dict] = []
    # Bound the in-flight queue so memory stays flat.
    queue: asyncio.Queue = asyncio.Queue(maxsize=concurrency * 2)

    async def producer() -> None:
        for rec in records:
            await queue.put(rec)
        for _ in range(concurrency):
            await queue.put(None)

    async def worker(
        client: httpx.AsyncClient, f, lock: asyncio.Lock
    ) -> None:
        while True:
            rec = await queue.get()
            if rec is None:
                return
            r = await one_request(client, sem, target, rec, timeout)
            line = json.dumps({"label": label, "target": target, **r})
            async with lock:
                f.write(line + "\n")
            summary_records.append(r)

    async with httpx.AsyncClient(limits=limits) as client:
        # Write raw results line-by-line.
        f = open(raw_path, "a")
        try:
            lock = asyncio.Lock()
            workers = [
                asyncio.create_task(worker(client, f, lock))
                for _ in range(concurrency)
            ]
            await producer()
            await asyncio.gather(*workers)
        finally:
            f.close()
    return summary_records


def summarize(label: str, target: str, results: list[dict]) -> list[dict]:
    """Per-class roll-up. Outputs one record per (label, class)."""
    by_class: dict[str, list[dict]] = {}
    for r in results:
        by_class.setdefault(r["class"], []).append(r)
    out = []
    for cls, rs in sorted(by_class.items()):
        n = len(rs)
        statuses = Counter(r["status"] for r in rs)
        blocked = sum(1 for r in rs if r["status"] == 403)
        passed = sum(1 for r in rs if 200 <= r["status"] < 300)
        errors = sum(1 for r in rs if r["status"] == 0)
        server_err = sum(1 for r in rs if 500 <= r["status"] < 600)
        elapsed = [r["elapsed_ms"] for r in rs if r["status"] != 0]
        elapsed.sort()

        def pct(p: float) -> float:
            if not elapsed:
                return 0.0
            i = max(0, min(len(elapsed) - 1, int(round(p * (len(elapsed) - 1)))))
            return elapsed[i]

        expected = rs[0]["expected_block"]
        rate = blocked / n if n else 0.0
        out.append({
            "label": label,
            "target": target,
            "class": cls,
            "expected_block": expected,
            "n": n,
            "blocked": blocked,
            "passed": passed,
            "server_err": server_err,
            "transport_err": errors,
            "rate_blocked": round(rate, 4),
            # By class semantics: for expected_block=True, rate_blocked
            # IS the TPR. For expected_block=False, rate_blocked IS the
            # FPR. Carrying both names so the downstream parser doesn't
            # have to remember.
            "tpr": round(rate, 4) if expected else None,
            "fpr": round(rate, 4) if not expected else None,
            "p50_ms": pct(0.50),
            "p95_ms": pct(0.95),
            "p99_ms": pct(0.99),
            "statuses": dict(statuses),
        })
    return out


async def main() -> int:
    args = parse_args()
    Path(args.out_summary).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out_raw).parent.mkdir(parents=True, exist_ok=True)

    records: list[dict] = []
    for src in (args.attacks, args.benign):
        with open(src) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    if args.max_requests > 0:
        records = records[: args.max_requests]

    print(
        f"[{args.label}] sending {len(records)} requests "
        f"at concurrency={args.concurrency} → {args.target}",
        flush=True,
    )
    # Truncate the raw output so re-runs don't append.
    open(args.out_raw, "w").close()
    t0 = time.perf_counter()
    results = await run_all_streaming(
        args.target,
        records,
        args.concurrency,
        args.per_request_timeout,
        args.out_raw,
        args.label,
    )
    wall = time.perf_counter() - t0
    print(
        f"[{args.label}] wall {wall:.1f}s ({len(results) / wall:.0f} rps avg)",
        flush=True,
    )

    summary = summarize(args.label, args.target, results)
    with open(args.out_summary, "a") as f:
        for s in summary:
            f.write(json.dumps(s) + "\n")

    # Print the summary table to stdout so kubectl logs surfaces it.
    print(f"\n=== efficacy summary ({args.label}) ===")
    print(f"{'class':10s} {'n':>5s} {'blocked':>9s} {'rate':>8s}")
    for s in summary:
        kind = "TPR" if s["expected_block"] else "FPR"
        print(
            f"{s['class']:10s} {s['n']:5d} {s['blocked']:9d} "
            f"{s['rate_blocked']:8.4f}  ({kind})"
        )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
