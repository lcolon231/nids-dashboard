"""Protocol-agnostic packet summary.

The capture layer (scapy) converts raw packets into PacketMeta so the flow
tracker and feature builder stay pure Python — testable without scapy, libpcap,
or root.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PacketMeta:
    """The subset of a packet the sensor needs."""

    ts: float
    src_ip: str
    dst_ip: str
    src_port: int  # 0 for ICMP
    dst_port: int  # 0 for ICMP
    proto: str  # "tcp" | "udp" | "icmp"
    payload_len: int = 0
    ip_len: int = 0  # total IP packet length (CIC packet-size features)
    tcp_flags: frozenset[str] = field(default_factory=frozenset)  # e.g. {"S","A"}
    tcp_window: int = -1  # receive window (CIC init_win features); -1 = n/a
    icmp_type: int = -1
    icmp_code: int = -1
    is_fragment: bool = False
