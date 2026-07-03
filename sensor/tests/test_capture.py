"""scapy packet -> PacketMeta conversion (skipped if scapy isn't installed)."""
import pytest

scapy = pytest.importorskip("scapy.layers.inet")
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402

from nids_sensor.capture import SensorEngine, packet_to_meta  # noqa: E402


def test_tcp_packet():
    pkt = IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000, dport=80, flags="PA") / b"hello"
    pkt.time = 123.0
    m = packet_to_meta(pkt)
    assert (m.proto, m.src_ip, m.dst_ip) == ("tcp", "10.0.0.5", "10.0.0.9")
    assert (m.src_port, m.dst_port) == (40000, 80)
    assert m.tcp_flags == frozenset("PA")
    assert m.payload_len == 5
    assert m.ts == 123.0


def test_udp_and_icmp_packets():
    u = packet_to_meta(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=5353, dport=53) / b"q")
    assert (u.proto, u.dst_port, u.payload_len) == ("udp", 53, 1)
    i = packet_to_meta(IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8))
    assert (i.proto, i.icmp_type) == ("icmp", 8)


def test_non_ip_returns_none():
    from scapy.layers.l2 import ARP, Ether

    assert packet_to_meta(Ether() / ARP()) is None


def test_engine_ignores_its_own_api_traffic():
    engine = SensorEngine("http://10.0.0.2:8000", batch_size=100)
    own = IP(src="10.0.0.5", dst="10.0.0.2") / TCP(sport=40000, dport=8000, flags="S")
    other = IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000, dport=80, flags="S")
    engine.on_packet(own)
    engine.on_packet(other)
    assert len(engine.tracker) == 1  # only the non-API flow is tracked
