"""End-to-end SensorEngine drive-through WITHOUT real network or root.

Feeds the REAL SensorEngine a full TCP connection (as scapy packets) and
asserts a completed connection produces a POST to /score/live. A mock httpx
transport stands in for the backend, exactly like test_sender.py.

If the emit path (on_packet -> tracker -> _emit_completed -> sender ->
tick/flush) is correct, these pass. If they fail, the bug is in the pure
pipeline rather than the scapy capture layer.
"""
import json

import httpx
import pytest

scapy = pytest.importorskip("scapy.layers.inet")
from scapy.layers.inet import IP, TCP  # noqa: E402

from nids_sensor.capture import SensorEngine  # noqa: E402
from nids_sensor.sender import LiveScoreSender  # noqa: E402


def _records_of(request):
    return json.loads(request.content)["records"]


def _mock_engine(calls, batch_size=10, flush_interval=2.0):
    """A SensorEngine whose sender POSTs into an in-memory mock transport."""
    def handler(request):
        calls.append(request)
        n = len(_records_of(request))
        return httpx.Response(200, json={"count": n, "attacks": 0, "results": []})

    engine = SensorEngine(
        "http://api.test:8000", batch_size=batch_size, flush_interval=flush_interval
    )
    client = httpx.Client(transport=httpx.MockTransport(handler))
    engine.sender = LiveScoreSender(
        "http://api.test:8000", batch_size=batch_size, client=client
    )
    return engine


def _tcp(src, dst, sport, dport, flags, ts, payload=b""):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload
    pkt.time = ts
    return pkt


def _full_connection(src="10.0.0.5", dst="10.0.0.9", sport=44444, dport=80, t0=1000.0):
    """SYN / SYN-ACK / ACK / data / FIN / FIN-ACK / ACK — a clean open+close."""
    return [
        _tcp(src, dst, sport, dport, "S", t0 + 0.0),
        _tcp(dst, src, dport, sport, "SA", t0 + 0.01),
        _tcp(src, dst, sport, dport, "A", t0 + 0.02),
        _tcp(src, dst, sport, dport, "PA", t0 + 0.03, b"GET / HTTP/1.0\r\n\r\n"),
        _tcp(dst, src, dport, sport, "PA", t0 + 0.04, b"HTTP/1.0 200 OK\r\n\r\n"),
        _tcp(src, dst, sport, dport, "FA", t0 + 0.05),
        _tcp(dst, src, dport, sport, "FA", t0 + 0.06),
        _tcp(src, dst, sport, dport, "A", t0 + 0.07),
    ]


def test_completed_connection_is_posted_via_tick():
    calls = []
    engine = _mock_engine(calls, batch_size=10, flush_interval=0.0)

    for pkt in _full_connection():
        engine.on_packet(pkt)

    # Flow finalized on the two FINs; record is buffered but batch not full,
    # so nothing has been POSTed yet.
    assert calls == []
    assert engine.sender.pending == 1

    # The periodic flush path (driven from the sweeper thread in production).
    engine.tick()

    assert len(calls) == 1, "tick() should flush the buffered record"
    assert calls[0].url.path == "/score/live"
    recs = _records_of(calls[0])
    assert len(recs) == 1
    rec = recs[0]
    assert rec["protocol_type"] == "tcp"
    assert rec["service"] == "http"
    assert rec["flag"] == "SF"  # normal establish + terminate


def test_full_batch_posts_immediately_on_packet():
    calls = []
    engine = _mock_engine(calls, batch_size=1)  # flush after every record

    for pkt in _full_connection():
        engine.on_packet(pkt)

    # batch_size=1 -> the finalized flow is POSTed the moment it is emitted.
    assert len(calls) == 1
    assert len(_records_of(calls[0])) == 1


def test_rst_finalizes_and_posts():
    calls = []
    engine = _mock_engine(calls, batch_size=1)
    engine.on_packet(_tcp("10.0.0.5", "10.0.0.9", 5555, 22, "S", 2000.0))
    engine.on_packet(_tcp("10.0.0.9", "10.0.0.5", 22, 5555, "R", 2000.1))
    assert len(calls) == 1  # RST closes the flow immediately


def test_tick_flushes_partial_batch_on_interval():
    calls = []
    engine = _mock_engine(calls, batch_size=100, flush_interval=0.0)
    for pkt in _full_connection(sport=33333):
        engine.on_packet(pkt)
    assert calls == []  # far below batch_size
    engine.tick()  # flush_interval=0 -> flush now
    assert len(calls) == 1


def test_idle_sweep_finalizes_open_flow():
    calls = []
    engine = _mock_engine(calls, batch_size=1, flush_interval=0.0)
    # An open flow (handshake only, never closed).
    engine.on_packet(_tcp("10.0.0.5", "10.0.0.9", 6000, 80, "S", 1.0))
    engine.on_packet(_tcp("10.0.0.9", "10.0.0.5", 80, 6000, "SA", 1.1))
    assert calls == []
    # Sweep with a 'now' far past the idle timeout finalizes it.
    engine.tracker.sweep(now=1.0 + engine.tracker._idle["tcp"] + 1.0)
    engine._emit_completed()
    assert len(calls) == 1
    assert _records_of(calls[0])[0]["flag"] == "S1"  # established, never terminated


def test_heartbeat_counters_track_pipeline():
    calls = []
    engine = _mock_engine(calls, batch_size=1)
    for pkt in _full_connection():
        engine.on_packet(pkt)
    stats = engine.stats()
    assert stats["packets"] == 8
    assert stats["non_ip"] == 0
    assert stats["finalized"] == 1
    assert stats["sent"] == 1
