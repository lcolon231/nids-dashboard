"""Live packet capture (scapy) -> flows -> features -> /score/live.

scapy is imported lazily so the rest of the package (and the test suite)
works without it. Capturing requires root or CAP_NET_RAW.
"""
from __future__ import annotations

import threading
import time
import traceback
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
    common["ip_len"] = int(ip.len) if ip.len is not None else len(ip)
    if TCP in pkt:
        tcp = pkt[TCP]
        return PacketMeta(
            src_port=tcp.sport,
            dst_port=tcp.dport,
            proto="tcp",
            payload_len=len(tcp.payload),
            tcp_flags=frozenset(str(tcp.flags)),
            tcp_window=int(tcp.window),
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
        schema: str = "nsl",  # "nsl" (41 KDD features) | "cic" (32 flow features)
        verbose: bool = False,
        stats_interval: float = 5.0,
    ) -> None:
        self.schema = schema
        self.tracker = FlowTracker(tcp_idle=idle_timeout)
        self.builder = FeatureBuilder()
        self.sender = LiveScoreSender(url, batch_size=batch_size, dataset=schema)
        self.flush_interval = flush_interval
        self._lock = threading.Lock()
        self._last_flush = time.time()
        self._sent = self._attacks = 0
        # Diagnostic counters (surfaced by --verbose via the heartbeat).
        self._pkts = 0          # packets handed to on_packet
        self._non_ip = 0        # dropped: not IP / unsupported L4
        self._own = 0           # dropped: sensor's own API traffic
        self._finalized = 0     # flows finalized (records emitted downstream)
        self._errors = 0        # exceptions swallowed in the packet path
        self._error_logged = False
        self.verbose = verbose
        self.stats_interval = stats_interval
        self._last_stats = time.time()
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
        # scapy's sniff() swallows exceptions raised in prn, so a single bad
        # packet would silently stop nothing being reported. Guard the whole
        # path and count/log failures instead of losing them.
        self._pkts += 1
        try:
            meta = packet_to_meta(pkt)
        except Exception as e:  # noqa: BLE001 — diagnostic guard, never crash capture
            self._record_error("decode", e)
            return
        if meta is None:
            self._non_ip += 1
            return
        if self._is_own_traffic(meta):
            self._own += 1
            return
        try:
            with self._lock:
                self.tracker.on_packet(meta)
                self._emit_completed()
        except Exception as e:  # noqa: BLE001 — diagnostic guard
            self._record_error("assemble", e)

    def _record_error(self, where: str, exc: Exception) -> None:
        self._errors += 1
        if not self._error_logged:
            self._error_logged = True
            print(f"[warn] packet {where} failed: {exc!r} (further errors counted silently)")
            traceback.print_exc()

    def tick(self) -> None:
        """Periodic: time out idle flows, flush stale batches."""
        with self._lock:
            self.tracker.sweep()
            self._emit_completed()
            if time.time() - self._last_flush >= self.flush_interval:
                self._report(self.sender.flush())
                self._last_flush = time.time()
        if self.verbose and time.time() - self._last_stats >= self.stats_interval:
            self._last_stats = time.time()
            print(self._heartbeat())

    def stats(self) -> dict:
        """Snapshot of the diagnostic counters (used by tests and heartbeat)."""
        return {
            "packets": self._pkts,
            "non_ip": self._non_ip,
            "own": self._own,
            "errors": self._errors,
            "open": len(self.tracker),
            "finalized": self._finalized,
            "buffered": self.sender.pending,
            "sent": self._sent,
            "flagged": self._attacks,
        }

    def _heartbeat(self) -> str:
        s = self.stats()
        return (
            f"[stat] pkts={s['packets']} non_ip={s['non_ip']} own={s['own']} "
            f"err={s['errors']} flows_open={s['open']} finalized={s['finalized']} "
            f"buffered={s['buffered']} sent={s['sent']} flagged={s['flagged']}"
        )

    def shutdown(self) -> None:
        with self._lock:
            self.tracker.flush_all()
            self._emit_completed()
            self._report(self.sender.flush())
            self.sender.close()
        print(f"[stop] sensor stopped — {self._sent} records scored, {self._attacks} flagged")

    def _emit_completed(self) -> None:
        for conn in self.tracker.drain():
            self._finalized += 1
            if self.schema == "cic":
                # protocol/service/flag ride along for the dashboard Live
                # Feed only — the CIC models never see them.
                record = {
                    **conn.cic,
                    "protocol_type": conn.proto,
                    "service": conn.service,
                    "flag": conn.flag,
                }
            else:
                record = self.builder.build(conn)
            self._report(self.sender.add(record))

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
    bpf: str = "",
    batch_size: int = 10,
    flush_interval: float = 2.0,
    idle_timeout: float = 30.0,
    schema: str = "nsl",
    verbose: bool = False,
) -> int:
    # Import from scapy.all (not scapy.sendrecv): scapy.all runs the full
    # layer/conf initialization — protocol dissectors and the L2 capture
    # socket setup — that a bare `from scapy.sendrecv import sniff` may skip.
    # On some interfaces (notably Raspberry Pi wlan0) the under-initialized
    # path can hand prn() undissected frames (no IP layer -> every packet
    # dropped as non-IP) or fail to open a usable capture socket at all.
    from scapy.all import sniff

    engine = SensorEngine(
        url, batch_size, flush_interval, idle_timeout, schema, verbose=verbose
    )
    stop = threading.Event()

    def sweeper() -> None:
        # A dead sweeper means flushes stop forever, so no exception may kill
        # this loop — log it and keep ticking.
        while not stop.wait(SWEEP_INTERVAL):
            try:
                engine.tick()
            except Exception as e:  # noqa: BLE001 — keep the flush loop alive
                print(f"[warn] sweeper tick failed: {e!r}")
                traceback.print_exc()

    t = threading.Thread(target=sweeper, daemon=True)
    t.start()
    # No BPF filter by default: on some interfaces (e.g. Raspberry Pi wlan0)
    # scapy can't identify the link type and a kernel BPF filter silently
    # drops every packet. packet_to_meta() already discards non-IP frames in
    # Python, so the filter is redundant; --bpf re-enables it if wanted.
    filter_desc = bpf or "none (IP filtered in software)"
    print(f"[ok  ] capturing on {iface or 'default iface'} (filter: {filter_desc}) -> {url}/score/live")
    if verbose:
        print(f"[ok  ] verbose heartbeat every {engine.stats_interval:.0f}s ([stat] lines)")
    try:
        sniff(iface=iface, filter=bpf or None, store=False, prn=engine.on_packet)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        t.join(timeout=2)
        engine.shutdown()
    return 0
