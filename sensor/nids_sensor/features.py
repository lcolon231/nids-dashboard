"""Derive the 41 NSL-KDD features from finalized connections.

Three feature groups are honestly derivable from packet capture:
  - intrinsic (duration, protocol_type, service, flag, bytes, land, ...)
  - time-based traffic stats over a 2-second window (count, serror_rate, ...)
  - host-based stats over the last 100 connections (dst_host_*)

The 13 content features (hot, num_file_creations, logged_in, ...) require
host-side telemetry or payload inspection the sensor doesn't have; they are
emitted as 0, exactly as documented in sensor/README.md.
"""
from __future__ import annotations

from collections import deque

from nids_sensor.flows import ConnRecord

# Must match backend/nids/data.py FEATURE_COLUMNS exactly.
FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
assert len(FEATURE_COLUMNS) == 41

# Flags counted as SYN errors / rejection errors in the KDD rate features.
SERROR_FLAGS = {"S0", "S1", "S2", "S3"}
REJ_FLAG = "REJ"

TIME_WINDOW_SECONDS = 2.0
HOST_WINDOW_CONNS = 100

CONTENT_ZEROS = {
    "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
    "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
    "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0,
    "is_host_login": 0, "is_guest_login": 0,
}


def _rate(subset: list[ConnRecord], pred) -> float:
    return round(sum(pred(c) for c in subset) / len(subset), 2) if subset else 0.0


class FeatureBuilder:
    """Keeps a rolling connection history and emits 41-feature records."""

    def __init__(self, history_size: int = 1000) -> None:
        self._history: deque[ConnRecord] = deque(maxlen=history_size)

    def build(self, conn: ConnRecord) -> dict:
        """Feature dict for `conn`; the connection itself joins the windows."""
        self._history.append(conn)

        # Time-based: connections in the past 2 seconds (incl. current).
        recent = [c for c in self._history if conn.ts - c.ts <= TIME_WINDOW_SECONDS]
        same_host = [c for c in recent if c.dst_ip == conn.dst_ip]
        same_srv = [c for c in recent if c.service == conn.service]

        serror = lambda c: c.flag in SERROR_FLAGS  # noqa: E731
        rerror = lambda c: c.flag == REJ_FLAG  # noqa: E731

        # Host-based: last 100 connections (incl. current).
        window = list(self._history)[-HOST_WINDOW_CONNS:]
        host_conns = [c for c in window if c.dst_ip == conn.dst_ip]
        host_srv = [c for c in host_conns if c.service == conn.service]
        win_srv = [c for c in window if c.service == conn.service]

        record: dict = {
            "duration": conn.duration,
            "protocol_type": conn.proto,
            "service": conn.service,
            "flag": conn.flag,
            "src_bytes": conn.src_bytes,
            "dst_bytes": conn.dst_bytes,
            "land": conn.land,
            "wrong_fragment": conn.wrong_fragment,
            "urgent": conn.urgent,
            **CONTENT_ZEROS,
            "count": len(same_host),
            "srv_count": len(same_srv),
            "serror_rate": _rate(same_host, serror),
            "srv_serror_rate": _rate(same_srv, serror),
            "rerror_rate": _rate(same_host, rerror),
            "srv_rerror_rate": _rate(same_srv, rerror),
            "same_srv_rate": _rate(same_host, lambda c: c.service == conn.service),
            "diff_srv_rate": _rate(same_host, lambda c: c.service != conn.service),
            "srv_diff_host_rate": _rate(same_srv, lambda c: c.dst_ip != conn.dst_ip),
            "dst_host_count": len(host_conns),
            "dst_host_srv_count": len(host_srv),
            "dst_host_same_srv_rate": _rate(host_conns, lambda c: c.service == conn.service),
            "dst_host_diff_srv_rate": _rate(host_conns, lambda c: c.service != conn.service),
            "dst_host_same_src_port_rate": _rate(host_conns, lambda c: c.src_port == conn.src_port),
            "dst_host_srv_diff_host_rate": _rate(win_srv, lambda c: c.dst_ip != conn.dst_ip),
            "dst_host_serror_rate": _rate(host_conns, serror),
            "dst_host_srv_serror_rate": _rate(host_srv, serror),
            "dst_host_rerror_rate": _rate(host_conns, rerror),
            "dst_host_srv_rerror_rate": _rate(host_srv, rerror),
        }
        return {col: record[col] for col in FEATURE_COLUMNS}
