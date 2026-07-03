"""Simulated Pi network sensor (Phase 9).

Samples random rows from KDDTest+ and POSTs them to /score/live in small
batches, mimicking a sensor streaming connection records. Swap this for the
real Raspberry Pi capture client later — the API contract is identical.

Usage:
    python sensor_sim.py [--interval 2] [--batch 5] [--url http://127.0.0.1:8000]
"""
from __future__ import annotations

import argparse
import random
import time

import httpx

from nids import data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between batches")
    ap.add_argument("--batch", type=int, default=5, help="records per batch")
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="API base URL")
    ap.add_argument("--count", type=int, default=0, help="stop after N batches (0 = forever)")
    args = ap.parse_args()

    pool = data.load("test").drop(columns=["label"])
    print(f"[ok  ] sensor pool: {len(pool)} records; posting {args.batch}/batch "
          f"every {args.interval}s -> {args.url}/score/live")

    sent = 0
    while args.count == 0 or sent < args.count:
        rows = pool.sample(args.batch, random_state=random.randrange(1 << 30))
        records = rows.to_dict(orient="records")
        try:
            r = httpx.post(f"{args.url}/score/live", json={"records": records}, timeout=30)
            r.raise_for_status()
            body = r.json()
            print(f"[sent] batch {sent + 1}: {body['attacks']}/{body['count']} flagged as attacks")
        except httpx.HTTPError as e:
            print(f"[warn] {e} — retrying next tick")
        sent += 1
        time.sleep(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
