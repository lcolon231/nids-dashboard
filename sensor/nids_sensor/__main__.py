"""Raspberry Pi NIDS sensor — capture live traffic, score it on the backend.

Usage (needs root or CAP_NET_RAW for packet capture):
    sudo .venv/bin/python -m nids_sensor --iface eth0 --url http://<backend>:8000
"""
from __future__ import annotations

import argparse

from nids_sensor.capture import run


def main() -> int:
    ap = argparse.ArgumentParser(prog="nids_sensor", description=__doc__)
    ap.add_argument("--url", default="http://127.0.0.1:8000", help="API base URL")
    ap.add_argument("--iface", default=None, help="interface to sniff (default: scapy's default)")
    ap.add_argument("--bpf", default="",
                    help="BPF capture filter (default: none; IP frames are "
                         "filtered in software). Set e.g. 'ip' to push filtering "
                         "into the kernel — but note some interfaces silently drop "
                         "all packets when a BPF filter is set with an unknown link type.")
    ap.add_argument("--batch", type=int, default=10, help="records per POST batch")
    ap.add_argument("--flush-interval", type=float, default=2.0,
                    help="max seconds before a partial batch is sent")
    ap.add_argument("--idle-timeout", type=float, default=30.0,
                    help="seconds of silence before an open TCP flow is finalized")
    ap.add_argument("--schema", choices=("nsl", "cic"), default="nsl",
                    help="feature schema / backend model family: nsl (41 KDD "
                         "features) or cic (32 modern flow features)")
    ap.add_argument("--verbose", "--stats", action="store_true", dest="verbose",
                    help="print a periodic [stat] heartbeat with pipeline "
                         "counters (packets seen, dropped non-IP/own, flows "
                         "open/finalized, records buffered/sent) — use this to "
                         "diagnose why no [sent] lines appear")
    args = ap.parse_args()
    return run(
        url=args.url,
        iface=args.iface,
        bpf=args.bpf,
        batch_size=args.batch,
        flush_interval=args.flush_interval,
        idle_timeout=args.idle_timeout,
        schema=args.schema,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    raise SystemExit(main())
