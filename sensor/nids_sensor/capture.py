"""Live packet capture (scapy) -> flows -> features -> /score/live.

scapy is imported lazily so the rest of the package (and the test suite)
works without it. Capturing requires root or CAP_NET_RAW.
"""
from __future__ import annotations

import threading
import time
from urllib.parse import urlparse

from nids_sensor.features import FeatureBuilder
from nids_sensor.flows import FlowTracker
from nids_sensor.packet import PacketMeta
from nids_sensor.sender import LiveScoreSender

SWEEP_INTERVAL = 1.0


def packet_to_meta(pkt) -> PacketMeta | None:
    """Convert a scapy packet to PacketMeta; None for non-IP/unsupported."""
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    if IP not in pkt:
        return None
    ip = pkt[IP]
    is_fragment = ip.frag > 0 or bool(ip.flags & 0x1)  # offset > 0 or MF set
    common = dict(
        ts=float(pkt.time),
        src_ip=ip.src,
        dst_ip=ip.dst,
        is_fragment=is_fragment,
    )
    if TCP in pkt:
        tcp = pkt[TCP]
        return PacketMeta(
            src_port=tcp.sport,
            dst_port=tcp.dport,
            proto="tcp",
            payload_len=len(tcp.payload),
            tcp_flags=frozenset(str(tcp.flags)),
            **common,
        )
    if UDP in pkt:
        udp = pkt[UDP]
        return PacketMeta(
            src_port=udp.sport,
            dst_port=udp.dport,
            proto="udp",
            payload_len=len(udp.payload),
            **common,
        )
    if ICMP in pkt:
        icmp = pkt[ICMP]
        return PacketMeta(
            src_port=0,
            dst_port=0,
            proto="icmp",
            payload_len=len(icmp.payload),
            icmp_type=int(icmp.type),
            icmp_code=int(icmp.code),
            **common,
        )
    return None


class SensorEngine:
    """Ties tracker + feature builder + sender together behind one lock."""

    def __init__(
        self,
        url: str,
        batch_size: int = 10,
        flush_interval: float = 2.0,
        idle_timeout: float = 30.0,
    ) -> None:
        self.tracker = FlowTracker(tcp_idle=idle_timeout)
        self.builder = FeatureBuilder()
        self.sender = LiveScoreSender(url, batch_size=batch_size)
        self.flush_interval = flush_interval
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._sent = self._attacks = 0
        # Ignore the sensor's own traffic to the API (avoid a feedback loop).
        api = urlparse(url)
        self._api_host = api.hostname
        self._api_port = api.port or (443 if api.scheme == "https" else 80)

    def _is_own_traffic(self, meta: PacketMeta) -> bool:
        return (
            meta.proto == "tcp"
            and self._api_port in (meta.src_port, meta.dst_port)
            and self._api_host in (meta.src_ip, meta.dst_ip)
        )

    def on_packet(self, pkt) -> None:
        meta = packet_to_meta(pkt)
        if meta is None or self._is_own_traffic(meta):
            return
        with self._lock:
            self.tracker.on_packet(meta)
            self._emit_completed()

    def tick(self) -> None:
        """Periodic: time out idle flows, flush stale batches."""
        with self._lock:
            self.tracker.sweep()
            self._emit_completed()
            if time.time() - self._last_flush >= self.flush_interval:
                self._report(self.sender.flush())
                self._last_flush = time.time()

    def shutdown(self) -> None:
        with self._lock:
            self.tracker.flush_all()
            self._emit_completed()
            self._report(self.sender.flush())
            self.sender.close()
        print(f"[stop] sensor stopped — {self._sent} records scored, {self._attacks} flagged")

    def _emit_completed(self) -> None:
        for conn in self.tracker.drain():
            self._report(self.sender.add(self.builder.build(conn)))

    def _report(self, body: dict | None) -> None:
        if body is None:
            return
        self._sent += body["count"]
        self._attacks += body["attacks"]
        print(
            f"[sent] {body['count']} records, {body['attacks']} flagged "
            f"(session: {self._attacks}/{self._sent})"
        )


def run(
    url: str,
    iface: str | None = None,
    bpf: str = "ip",
    batch_size: int = 10,
    flush_interval: float = 2.0,
    idle_timeout: float = 30.0,
) -> int:
    from scapy.sendrecv import sniff

    engine = SensorEngine(url, batch_size, flush_interval, idle_timeout)
    stop = threading.Event()

    def sweeper() -> None:
        while not stop.wait(SWEEP_INTERVAL):
            engine.tick()

    t = threading.Thread(target=sweeper, daemon=True)
    t.start()
    print(f"[ok  ] capturing on {iface or 'default iface'} (filter: {bpf!r}) -> {url}/score/live")
    try:
        sniff(iface=iface, filter=bpf, store=False, prn=engine.on_packet)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        t.join(timeout=2)
        engine.shutdown()
    return 0
