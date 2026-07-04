"""CIC-style flow features: running stats, per-flow derivation, backend parity."""
import ast
from pathlib import Path

import pytest

from nids_sensor.flow_features import FLOW_FEATURES
from nids_sensor.flows import FlowTracker, RunningStats
from nids_sensor.packet import PacketMeta

C, S = "10.0.0.5", "10.0.0.9"


def pkt(ts, src, sport, dst, dport, flags="", plen=0, ip_len=0, window=-1):
    return PacketMeta(
        ts=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        proto="tcp", payload_len=plen, ip_len=ip_len,
        tcp_flags=frozenset(flags), tcp_window=window,
    )


class TestRunningStats:
    def test_empty_is_all_zero(self):
        s = RunningStats()
        assert (s.count, s.total, s.mean, s.std, s.min, s.max) == (0, 0.0, 0.0, 0.0, 0.0, 0.0)

    def test_stats(self):
        s = RunningStats()
        for x in (2, 4, 4, 4, 5, 5, 7, 9):
            s.add(x)
        assert s.count == 8
        assert s.total == 40
        assert s.mean == 5.0
        assert s.std == 2.0  # classic population-std example
        assert (s.min, s.max) == (2, 9)


class TestCicFeatures:
    @pytest.fixture
    def record(self):
        t = FlowTracker()
        t.on_packet(pkt(0.0, C, 40000, S, 80, "S", ip_len=60, window=64240))
        t.on_packet(pkt(0.1, S, 80, C, 40000, "SA", ip_len=60, window=65535))
        t.on_packet(pkt(0.2, C, 40000, S, 80, "A", ip_len=52))
        t.on_packet(pkt(0.3, C, 40000, S, 80, "PA", plen=100, ip_len=152))
        t.on_packet(pkt(0.5, S, 80, C, 40000, "PA", plen=500, ip_len=552))
        t.on_packet(pkt(1.0, C, 40000, S, 80, "FA", ip_len=52))
        t.on_packet(pkt(1.2, S, 80, C, 40000, "FA", ip_len=52))
        records = t.drain()
        assert len(records) == 1
        return records[0]

    def test_schema_complete_and_ordered(self, record):
        assert list(record.cic.keys()) == FLOW_FEATURES

    def test_counts_bytes_and_duration(self, record):
        f = record.cic
        assert f["dst_port"] == 80
        assert f["flow_duration"] == pytest.approx(1_200_000)  # µs
        assert (f["tot_fwd_pkts"], f["tot_bwd_pkts"]) == (4, 3)
        assert (f["tot_fwd_bytes"], f["tot_bwd_bytes"]) == (316, 664)
        assert f["fwd_pkt_len_max"] == 152
        assert f["fwd_pkt_len_min"] == 52
        assert f["fwd_pkt_len_mean"] == 79.0
        assert f["bwd_pkt_len_max"] == 552

    def test_rates_and_ratios(self, record):
        f = record.cic
        assert f["flow_bytes_per_s"] == pytest.approx(980 / 1.2)
        assert f["flow_pkts_per_s"] == pytest.approx(7 / 1.2)
        assert f["down_up_ratio"] == 0.75
        assert f["avg_pkt_size"] == pytest.approx(140.0)

    def test_inter_arrival_times_in_us(self, record):
        f = record.cic
        assert f["flow_iat_mean"] == pytest.approx(200_000)  # 1.2s over 6 gaps
        assert f["flow_iat_max"] == pytest.approx(500_000)
        assert f["flow_iat_min"] == pytest.approx(100_000)
        assert f["fwd_iat_mean"] == pytest.approx(1_000_000 / 3)
        assert f["bwd_iat_mean"] == pytest.approx(550_000)

    def test_flag_counts_and_init_windows(self, record):
        f = record.cic
        assert f["syn_flag_cnt"] == 2  # SYN + SYN-ACK
        assert f["fin_flag_cnt"] == 2
        assert f["ack_flag_cnt"] == 6
        assert f["psh_flag_cnt"] == 2
        assert (f["rst_flag_cnt"], f["urg_flag_cnt"]) == (0, 0)
        assert f["init_win_bytes_fwd"] == 64240
        assert f["init_win_bytes_bwd"] == 65535

    def test_single_packet_flow_has_no_nans(self):
        t = FlowTracker()
        t.on_packet(pkt(0.0, C, 40000, S, 443, "S", ip_len=60))
        t.flush_all()
        f = t.drain()[0].cic
        assert f["flow_duration"] == 0
        assert f["flow_bytes_per_s"] == 0.0  # zero-duration guard
        assert f["bwd_pkt_len_mean"] == 0.0  # no bwd packets
        assert f["init_win_bytes_fwd"] == -1  # window not captured
        assert all(v == v for v in f.values())  # no NaN


def test_schema_matches_backend_flowschema():
    """FLOW_FEATURES must equal backend/nids/flowschema.py's CIC_COLUMN_MAP keys."""
    backend = Path(__file__).resolve().parents[2] / "backend" / "nids" / "flowschema.py"
    if not backend.exists():
        pytest.skip("backend not checked out alongside sensor")
    tree = ast.parse(backend.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "CIC_COLUMN_MAP":
            backend_features = [ast.literal_eval(k) for k in node.value.keys]
            break
    else:
        pytest.fail("CIC_COLUMN_MAP not found in backend flowschema")
    assert backend_features == FLOW_FEATURES
