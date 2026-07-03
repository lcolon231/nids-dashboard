"""Flow assembly + TCP state machine -> NSL-KDD flag."""
from nids_sensor.flows import FlowTracker
from nids_sensor.packet import PacketMeta


def pkt(ts, src, sport, dst, dport, proto="tcp", flags="", plen=0, **kw):
    return PacketMeta(
        ts=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        proto=proto, payload_len=plen, tcp_flags=frozenset(flags), **kw,
    )


def only_record(tracker):
    records = tracker.drain()
    assert len(records) == 1
    return records[0]


C, S = "10.0.0.5", "10.0.0.9"  # client (originator), server (responder)


def handshake(t, ts=0.0, sport=40000, dport=80, dst=S):
    t.on_packet(pkt(ts, C, sport, dst, dport, flags="S"))
    t.on_packet(pkt(ts + 0.01, dst, dport, C, sport, flags="SA"))
    t.on_packet(pkt(ts + 0.02, C, sport, dst, dport, flags="A"))


def test_normal_connection_is_sf_with_byte_accounting():
    t = FlowTracker()
    handshake(t)
    t.on_packet(pkt(0.1, C, 40000, S, 80, flags="PA", plen=120))
    t.on_packet(pkt(0.2, S, 80, C, 40000, flags="PA", plen=900))
    t.on_packet(pkt(5.0, C, 40000, S, 80, flags="FA"))
    t.on_packet(pkt(5.1, S, 80, C, 40000, flags="FA"))
    r = only_record(t)
    assert (r.flag, r.service, r.proto) == ("SF", "http", "tcp")
    assert (r.src_bytes, r.dst_bytes) == (120, 900)
    assert r.duration == 5
    assert (r.src_ip, r.dst_ip) == (C, S)


def test_unanswered_syn_times_out_as_s0():
    t = FlowTracker(tcp_idle=30)
    t.on_packet(pkt(0.0, C, 40000, S, 23, flags="S"))
    t.sweep(now=10.0)
    assert t.drain() == []  # not idle long enough yet
    t.sweep(now=31.0)
    assert only_record(t).flag == "S0"


def test_syn_rst_from_responder_is_rej():
    t = FlowTracker()
    t.on_packet(pkt(0.0, C, 40000, S, 22, flags="S"))
    t.on_packet(pkt(0.01, S, 22, C, 40000, flags="RA"))
    assert only_record(t).flag == "REJ"


def test_established_then_rst():
    for who, want in [("orig", "RSTO"), ("resp", "RSTR")]:
        t = FlowTracker()
        handshake(t)
        if who == "orig":
            t.on_packet(pkt(1.0, C, 40000, S, 80, flags="R"))
        else:
            t.on_packet(pkt(1.0, S, 80, C, 40000, flags="R"))
        assert only_record(t).flag == want, who


def test_syn_then_fin_no_synack_is_sh():
    t = FlowTracker(tcp_idle=30)
    t.on_packet(pkt(0.0, C, 40000, S, 80, flags="S"))
    t.on_packet(pkt(0.1, C, 40000, S, 80, flags="F"))
    t.sweep(now=60.0)
    assert only_record(t).flag == "SH"


def test_midstream_traffic_is_oth():
    t = FlowTracker(tcp_idle=30)
    t.on_packet(pkt(0.0, C, 40000, S, 80, flags="PA", plen=50))
    t.sweep(now=60.0)
    assert only_record(t).flag == "OTH"


def test_udp_and_icmp_flows():
    t = FlowTracker(udp_idle=10, icmp_idle=5)
    t.on_packet(pkt(0.0, C, 5353, S, 53, proto="udp", plen=40))
    t.on_packet(pkt(0.1, S, 53, C, 5353, proto="udp", plen=200))
    t.on_packet(pkt(0.0, C, 0, S, 0, proto="icmp", icmp_type=8, icmp_code=0))
    t.on_packet(pkt(0.1, S, 0, C, 0, proto="icmp", icmp_type=0, icmp_code=0))
    t.sweep(now=100.0)
    records = {r.proto: r for r in t.drain()}
    assert records["udp"].flag == "SF"
    assert records["udp"].service == "domain_u"
    assert (records["udp"].src_bytes, records["udp"].dst_bytes) == (40, 200)
    assert records["icmp"].service == "eco_i"  # originator's echo request


def test_land_packet_detected():
    t = FlowTracker()
    t.on_packet(pkt(0.0, C, 80, C, 80, flags="S"))
    t.flush_all()
    assert only_record(t).land == 1


def test_urgent_and_fragment_counters():
    t = FlowTracker()
    handshake(t)
    t.on_packet(pkt(0.5, C, 40000, S, 80, flags="UA", plen=10))
    t.on_packet(pkt(0.6, C, 40000, S, 80, flags="A", plen=10, is_fragment=True))
    t.flush_all()
    r = only_record(t)
    assert (r.urgent, r.wrong_fragment) == (1, 1)


def test_flush_all_empties_tracker():
    t = FlowTracker()
    t.on_packet(pkt(0.0, C, 1, S, 80, flags="S"))
    t.on_packet(pkt(0.0, C, 2, S, 80, flags="S"))
    assert len(t) == 2
    t.flush_all()
    assert len(t) == 0
    assert len(t.drain()) == 2
