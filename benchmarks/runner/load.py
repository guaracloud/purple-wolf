"""Constant-RPS load runner using vegeta.

Drives vegeta at each requested RPS level against the target for a
fixed duration, records latency percentiles + error rate, optionally
records resource usage of the target's traefik container in parallel.

Usage:
  python load.py \\
    --target http://bench-pw:8080 \\
    --label  purple-wolf \\
    --targets-file /corpus/load-targets.txt \\
    --rps 100,500,1000 \\
    --duration 30s \\
    --iters 2 \\
    --out /out/load.jsonl
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--targets-file", required=True)
    p.add_argument(
        "--rps",
        default="100,500,1000",
        help="comma-separated RPS levels to test",
    )
    p.add_argument("--duration", default="30s")
    p.add_argument("--iters", type=int, default=2)
    p.add_argument("--warmup-seconds", type=int, default=5)
    p.add_argument("--out", required=True)
    return p.parse_args()


def vegeta_attack(targets_file: str, rate: int, duration: str) -> dict:
    """Run one vegeta attack; return its JSON report."""
    # vegeta attack ... | vegeta report -type=json
    attack = subprocess.Popen(
        [
            "vegeta",
            "attack",
            "-rate",
            f"{rate}/s",
            "-duration",
            duration,
            "-targets",
            targets_file,
            "-keepalive",
            "true",
            "-timeout",
            "5s",
        ],
        stdout=subprocess.PIPE,
    )
    report = subprocess.run(
        ["vegeta", "report", "-type=json"],
        stdin=attack.stdout,
        capture_output=True,
        text=True,
        check=False,
    )
    attack.wait()
    if not report.stdout.strip():
        sys.stderr.write(report.stderr)
        return {}
    return json.loads(report.stdout)


def warmup(target: str, seconds: int) -> None:
    """Light warm-up to get connection pools + plugin compilation
    out of the cold-start phase before measurement."""
    end = time.time() + seconds
    while time.time() < end:
        subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-m",
                "1",
                target + "/",
            ],
            check=False,
        )


def main() -> int:
    args = parse_args()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    rps_levels = [int(s) for s in args.rps.split(",")]
    rewrite_targets(args.targets_file, args.target)
    print(
        f"[{args.label}] warmup {args.warmup_seconds}s "
        f"against {args.target} …",
        flush=True,
    )
    warmup(args.target, args.warmup_seconds)

    for rate in rps_levels:
        for it in range(args.iters):
            print(
                f"[{args.label}] rps={rate} iter={it + 1}/{args.iters} "
                f"duration={args.duration} …",
                flush=True,
            )
            t0 = time.time()
            rep = vegeta_attack(args.targets_file, rate, args.duration)
            wall = time.time() - t0
            if not rep:
                print(
                    f"[{args.label}] FAIL: vegeta produced no report",
                    flush=True,
                )
                continue
            # Latencies are in ns in vegeta JSON.
            lat = rep["latencies"]
            line = {
                "label": args.label,
                "target": args.target,
                "rps_target": rate,
                "iter": it,
                "duration": args.duration,
                "requests": rep["requests"],
                "rate_actual": round(rep["rate"], 2),
                "throughput": round(rep["throughput"], 2),
                "success": rep["success"],
                "status_codes": rep["status_codes"],
                "errors": rep.get("errors") or [],
                "latency_ms": {
                    "p50": round(lat["50th"] / 1e6, 3),
                    "p95": round(lat["95th"] / 1e6, 3),
                    "p99": round(lat["99th"] / 1e6, 3),
                    "max": round(lat["max"] / 1e6, 3),
                    "mean": round(lat["mean"] / 1e6, 3),
                },
                "wall_seconds": round(wall, 2),
            }
            with open(args.out, "a") as f:
                f.write(json.dumps(line) + "\n")
            print(
                f"  → rate={line['rate_actual']:.0f}/s "
                f"p50={line['latency_ms']['p50']:.1f}ms "
                f"p95={line['latency_ms']['p95']:.1f}ms "
                f"p99={line['latency_ms']['p99']:.1f}ms "
                f"success={line['success']:.4f}",
                flush=True,
            )
    return 0


def rewrite_targets(targets_file: str, target: str) -> None:
    """The committed targets file has placeholder hostnames; rewrite
    to the actual target for this run."""
    p = Path(targets_file)
    text = p.read_text()
    new = text.replace("__TARGET__", target.rstrip("/"))
    if new != text:
        p.write_text(new)


if __name__ == "__main__":
    sys.exit(main())
