"""Bidirectional flow assembly + NSL-KDD connection-state flags.

Packets are grouped into flows by (src_ip, src_port, dst_ip, dst_port, proto);
the first packet seen defines the originator. A simplified Bro/Zeek-style TCP
state machine yields the NSL-KDD `flag` value when the flow finalizes (on RST,
on both FINs, or on idle timeout via sweep()).
"""
from __future__ import annotations

import time
from dataclasses import dataclass

from nids_sensor.packet import PacketMeta
from nids_sensor.services import service_name

FlowKey = tuple[str, int, str, int, str]


@dataclass
class ConnRecord:
    """A finalized connection, ready for feature derivation."""

    ts: float  # end time
    duration: int
    proto: str
    service: str
    flag: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    src_bytes: int
    dst_bytes: int
    land: int
    wrong_fragment: int
    urgent: int


class Flow:
    def __init__(self, meta: PacketMeta) -> None:
        self.proto = meta.proto
        self.src_ip, self.src_port = meta.src_ip, meta.src_port
        self.dst_ip, self.dst_port = meta.dst_ip, meta.dst_port
        self.first_ts = self.last_ts = meta.ts
        self.icmp_type, self.icmp_code = meta.icmp_type, meta.icmp_code
        self.src_bytes = self.dst_bytes = 0
        self.wrong_fragment = self.urgent = 0
        self.syn_seen = self.synack_seen = False
        self.orig_fin = self.resp_fin = False
        self.orig_rst = self.resp_rst = False
        self.update(meta, from_orig=True)

    def update(self, meta: PacketMeta, from_orig: bool) -> None:
        self.last_ts = max(self.last_ts, meta.ts)
        if from_orig:
            self.src_bytes += meta.payload_len
        else:
            self.dst_bytes += meta.payload_len
        if meta.is_fragment:
            self.wrong_fragment += 1
        flags = meta.tcp_flags
        if self.proto != "tcp":
            return
        if "U" in flags:
            self.urgent += 1
        if from_orig:
            if "S" in flags and "A" not in flags:
                self.syn_seen = True
            self.orig_fin = self.orig_fin or "F" in flags
            self.orig_rst = self.orig_rst or "R" in flags
        else:
            if "S" in flags and "A" in flags:
                self.synack_seen = True
            self.resp_fin = self.resp_fin or "F" in flags
            self.resp_rst = self.resp_rst or "R" in flags

    @property
    def closed(self) -> bool:
        if self.proto != "tcp":
            return False
        return self.orig_rst or self.resp_rst or (self.orig_fin and self.resp_fin)

    def flag(self) -> str:
        """NSL-KDD connection-state flag (simplified Bro semantics)."""
        if self.proto != "tcp":
            return "SF"
        if not self.syn_seen:
            return "OTH"  # midstream — no handshake observed
        if not self.synack_seen:
            if self.resp_rst:
                return "REJ"  # connection rejected
            if self.orig_rst:
                return "RSTOS0"  # SYN then RST from originator
            if self.orig_fin:
                return "SH"  # SYN then FIN, no SYN-ACK (half-open scan)
            return "S0"  # SYN, no reply
        if self.orig_rst:
            return "RSTO"
        if self.resp_rst:
            return "RSTR"
        if self.orig_fin and self.resp_fin:
            return "SF"  # normal establish + terminate
        if self.orig_fin:
            return "S2"  # originator closed, responder didn't
        if self.resp_fin:
            return "S3"
        return "S1"  # established, never terminated

    def to_record(self) -> ConnRecord:
        return ConnRecord(
            ts=self.last_ts,
            duration=int(self.last_ts - self.first_ts),
            proto=self.proto,
            service=service_name(self.proto, self.dst_port, self.icmp_type, self.icmp_code),
            flag=self.flag(),
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            src_bytes=self.src_bytes,
            dst_bytes=self.dst_bytes,
            land=int(self.src_ip == self.dst_ip and self.src_port == self.dst_port),
            wrong_fragment=self.wrong_fragment,
            urgent=self.urgent,
        )


class FlowTracker:
    """Assembles packets into flows; finalized flows accumulate until drain()."""

    def __init__(
        self, tcp_idle: float = 30.0, udp_idle: float = 10.0, icmp_idle: float = 5.0
    ) -> None:
        self._idle = {"tcp": tcp_idle, "udp": udp_idle, "icmp": icmp_idle}
        self._flows: dict[FlowKey, Flow] = {}
        self._completed: list[ConnRecord] = []

    def __len__(self) -> int:
        return len(self._flows)

    def on_packet(self, meta: PacketMeta) -> None:
        key: FlowKey = (meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, meta.proto)
        rkey: FlowKey = (meta.dst_ip, meta.dst_port, meta.src_ip, meta.src_port, meta.proto)
        if key in self._flows:
            flow, from_orig = self._flows[key], True
        elif rkey in self._flows:
            flow, key, from_orig = self._flows[rkey], rkey, False
        else:
            self._flows[key] = Flow(meta)
            return
        flow.update(meta, from_orig)
        if flow.closed:
            self._finalize(key)

    def sweep(self, now: float | None = None) -> None:
        """Finalize flows idle past their per-protocol timeout."""
        now = time.time() if now is None else now
        stale = [
            k for k, f in self._flows.items() if now - f.last_ts > self._idle[f.proto]
        ]
        for key in stale:
            self._finalize(key)

    def flush_all(self) -> None:
        """Finalize every open flow (shutdown)."""
        for key in list(self._flows):
            self._finalize(key)

    def drain(self) -> list[ConnRecord]:
        done, self._completed = self._completed, []
        return done

    def _finalize(self, key: FlowKey) -> None:
        self._completed.append(self._flows.pop(key).to_record())
