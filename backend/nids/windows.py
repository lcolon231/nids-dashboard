"""Per-source-IP time-window aggregation (Phase 11).

The supervised models score each connection in isolation, which is
structurally blind to scans and floods: a single dropped-SYN probe is nearly
indistinguishable from a stray packet. The attack only becomes visible in the
*aggregate* — one source touching hundreds of ports in a few seconds. This
module groups finalized flows by source IP into fixed time windows and emits a
feature vector per (source, window) describing that source's fan-out and
failure behavior, which the anomaly model (nids/anomaly.py) then scores.

Each flow the sensor posts carries a `meta` block:
    {"src_ip", "dst_ip", "dst_port", "flag", "bytes"}
Flows without meta (e.g. the raw KDDTest+ sensor_sim) are ignored here.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Connection-state flags (NSL-KDD style, emitted for both schemas by the
# sensor) that indicate a failed / unanswered connection attempt — the
# signature of a scan sweeping closed or filtered ports.
FAILED_FLAGS = frozenset({"S0", "S1", "S2", "S3", "REJ", "RSTO", "RSTR", "SH", "OTH"})

WINDOW_FEATURES = [
    "flow_count",           # flows from this source in the window
    "distinct_dst_ports",   # unique destination ports (port-scan fan-out)
    "distinct_dst_hosts",   # unique destination hosts (host-sweep fan-out)
    "failed_ratio",         # fraction of flows that never established
    "ports_per_host",       # distinct ports / distinct hosts
    "total_bytes",          # total bytes moved (flood volume)
    "mean_bytes",           # mean bytes/flow (scans are tiny, floods vary)
]


@dataclass
class _SourceWindow:
    """Accumulates one source IP's flows within a single time window."""

    src_ip: str
    window_start: float
    flow_count: int = 0
    failed: int = 0
    total_bytes: float = 0.0
    dst_ports: set = field(default_factory=set)
    dst_hosts: set = field(default_factory=set)

    def add(self, meta: dict) -> None:
        self.flow_count += 1
        self.total_bytes += float(meta.get("bytes") or 0)
        if meta.get("flag") in FAILED_FLAGS:
            self.failed += 1
        if meta.get("dst_port") is not None:
            self.dst_ports.add(meta["dst_port"])
        if meta.get("dst_ip") is not None:
            self.dst_hosts.add(meta["dst_ip"])

    def features(self) -> dict:
        hosts = len(self.dst_hosts) or 1
        return {
            "src_ip": self.src_ip,
            "window_start": self.window_start,
            "flow_count": self.flow_count,
            "distinct_dst_ports": len(self.dst_ports),
            "distinct_dst_hosts": len(self.dst_hosts),
            "failed_ratio": round(self.failed / self.flow_count, 4) if self.flow_count else 0.0,
            "ports_per_host": round(len(self.dst_ports) / hosts, 4),
            "total_bytes": self.total_bytes,
            "mean_bytes": round(self.total_bytes / self.flow_count, 2) if self.flow_count else 0.0,
        }


class WindowAggregator:
    """Buckets flows into fixed [t0, t0+window) windows keyed by source IP.

    Call add() per flow, then pop_finalized(now) to harvest windows whose end
    has passed. Time is taken from each flow's own timestamp (meta may include
    an event time; otherwise the caller passes now), so this works both live
    and when replaying.
    """

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        # (src_ip, window_start) -> _SourceWindow
        self._open: dict[tuple[str, float], _SourceWindow] = {}

    def __len__(self) -> int:
        return len(self._open)

    def _window_start(self, ts: float) -> float:
        return ts - (ts % self.window_seconds)

    def add(self, meta: dict, ts: float) -> None:
        """Record one flow. `meta` needs at least src_ip; missing -> ignored."""
        src = meta.get("src_ip")
        if not src:
            return
        start = self._window_start(ts)
        key = (src, start)
        win = self._open.get(key)
        if win is None:
            win = self._open[key] = _SourceWindow(src_ip=src, window_start=start)
        win.add(meta)

    def pop_finalized(self, now: float) -> list[dict]:
        """Return + remove feature dicts for every window that has fully closed
        (its end is at or before `now`). Newest windows stay open."""
        done = [
            key
            for key, win in self._open.items()
            if win.window_start + self.window_seconds <= now
        ]
        out = [self._open.pop(key).features() for key in done]
        out.sort(key=lambda f: f["window_start"])
        return out

    def flush_all(self) -> list[dict]:
        """Emit every open window regardless of time (shutdown / tests)."""
        out = [win.features() for win in self._open.values()]
        self._open.clear()
        out.sort(key=lambda f: f["window_start"])
        return out
