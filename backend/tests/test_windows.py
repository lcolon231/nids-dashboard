"""Per-source window aggregation (Phase 11)."""
from nids.windows import WINDOW_FEATURES, WindowAggregator


def meta(src="10.0.0.5", dst="10.0.0.9", port=80, flag="SF", nbytes=100):
    return {"src_ip": src, "dst_ip": dst, "dst_port": port, "flag": flag, "bytes": nbytes}


class TestAggregation:
    def test_groups_by_source_and_window(self):
        agg = WindowAggregator(window_seconds=60)
        agg.add(meta(src="A"), ts=10)
        agg.add(meta(src="A"), ts=20)   # same 0-60 window
        agg.add(meta(src="B"), ts=30)   # different source, same window
        agg.add(meta(src="A"), ts=70)   # source A, next window (60-120)
        assert len(agg) == 3  # (A,0), (B,0), (A,60)

    def test_records_without_src_ignored(self):
        agg = WindowAggregator()
        agg.add({"dst_ip": "x", "dst_port": 1}, ts=1)  # no src_ip
        assert len(agg) == 0

    def test_feature_vector_shape(self):
        agg = WindowAggregator()
        agg.add(meta(), ts=1)
        w = agg.flush_all()[0]
        for f in WINDOW_FEATURES:
            assert f in w
        assert w["src_ip"] == "10.0.0.5"


class TestPortScanSignature:
    def test_scan_has_high_fanout_and_failed_ratio(self):
        agg = WindowAggregator(window_seconds=60)
        # one source hitting 100 ports on one host, all unanswered (S0)
        for port in range(100):
            agg.add(meta(src="attacker", dst="victim", port=port, flag="S0", nbytes=0), ts=5)
        w = agg.flush_all()[0]
        assert w["flow_count"] == 100
        assert w["distinct_dst_ports"] == 100
        assert w["distinct_dst_hosts"] == 1
        assert w["failed_ratio"] == 1.0
        assert w["ports_per_host"] == 100.0
        assert w["total_bytes"] == 0

    def test_normal_browsing_has_low_fanout(self):
        agg = WindowAggregator(window_seconds=60)
        # a few established connections to one web host
        for _ in range(5):
            agg.add(meta(src="user", dst="web", port=443, flag="SF", nbytes=5000), ts=5)
        w = agg.flush_all()[0]
        assert w["distinct_dst_ports"] == 1
        assert w["failed_ratio"] == 0.0
        assert w["mean_bytes"] == 5000


class TestFinalization:
    def test_pop_finalized_only_returns_closed_windows(self):
        agg = WindowAggregator(window_seconds=60)
        agg.add(meta(src="A"), ts=10)    # window [0,60)
        agg.add(meta(src="A"), ts=130)   # window [120,180)
        # now=90: window [0,60) is closed (ends at 60<=90), [120,180) still open
        done = agg.pop_finalized(now=90)
        assert len(done) == 1
        assert done[0]["window_start"] == 0
        assert len(agg) == 1  # the [120,180) window remains

    def test_pop_finalized_is_idempotent(self):
        agg = WindowAggregator(window_seconds=60)
        agg.add(meta(), ts=10)
        assert len(agg.pop_finalized(now=90)) == 1
        assert agg.pop_finalized(now=200) == []  # already harvested

    def test_windows_sorted_by_start(self):
        agg = WindowAggregator(window_seconds=60)
        agg.add(meta(src="A"), ts=130)
        agg.add(meta(src="B"), ts=10)
        out = agg.flush_all()
        assert [w["window_start"] for w in out] == [0, 120]
