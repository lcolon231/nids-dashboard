"""41-feature derivation: schema, window stats, content zeros."""
from nids_sensor.features import FEATURE_COLUMNS, CONTENT_ZEROS, FeatureBuilder
from nids_sensor.flows import ConnRecord


def conn(ts, dst="10.0.0.9", service="http", flag="SF", src_port=40000, **kw):
    defaults = dict(
        duration=0, proto="tcp", src_ip="10.0.0.5", src_bytes=100, dst_bytes=500,
        land=0, wrong_fragment=0, urgent=0, dst_port=80,
    )
    defaults.update(kw)
    return ConnRecord(ts=ts, dst_ip=dst, service=service, flag=flag,
                      src_port=src_port, **defaults)


def test_record_has_exactly_the_41_nsl_kdd_features_in_order():
    rec = FeatureBuilder().build(conn(0.0))
    assert list(rec.keys()) == FEATURE_COLUMNS
    assert len(rec) == 41


def test_content_features_are_zero():
    rec = FeatureBuilder().build(conn(0.0))
    for name in CONTENT_ZEROS:
        assert rec[name] == 0, name


def test_intrinsics_pass_through():
    rec = FeatureBuilder().build(
        conn(3.0, duration=5, src_bytes=42, dst_bytes=7, land=1, urgent=2)
    )
    assert rec["duration"] == 5
    assert rec["protocol_type"] == "tcp"
    assert rec["service"] == "http"
    assert rec["flag"] == "SF"
    assert (rec["src_bytes"], rec["dst_bytes"]) == (42, 7)
    assert (rec["land"], rec["urgent"]) == (1, 2)


def test_two_second_window_counts():
    fb = FeatureBuilder()
    fb.build(conn(0.0))                     # in window at t=1.5
    fb.build(conn(1.0))                     # in window
    fb.build(conn(1.2, dst="10.0.0.77"))    # other host, same service
    rec = fb.build(conn(1.5))
    assert rec["count"] == 3        # same dst host within 2s (incl. current)
    assert rec["srv_count"] == 4    # same service within 2s (any host)
    assert rec["same_srv_rate"] == 1.0
    assert rec["srv_diff_host_rate"] == 0.25

    rec = fb.build(conn(10.0))      # window expired -> only itself
    assert rec["count"] == 1
    assert rec["srv_count"] == 1


def test_syn_flood_burst_has_serror_rate_one():
    fb = FeatureBuilder()
    for i in range(9):
        fb.build(conn(i * 0.1, flag="S0", src_port=40000 + i))
    rec = fb.build(conn(0.95, flag="S0", src_port=40010))
    assert rec["count"] == 10
    assert rec["serror_rate"] == 1.0
    assert rec["srv_serror_rate"] == 1.0
    assert rec["dst_host_serror_rate"] == 1.0


def test_rejected_scan_has_rerror_rate():
    fb = FeatureBuilder()
    fb.build(conn(0.0, flag="REJ"))
    rec = fb.build(conn(0.5, flag="SF"))
    assert rec["rerror_rate"] == 0.5
    assert rec["dst_host_rerror_rate"] == 0.5


def test_host_window_spans_beyond_two_seconds():
    fb = FeatureBuilder()
    for i in range(30):
        fb.build(conn(float(i * 10), service="http" if i % 2 else "telnet"))
    rec = fb.build(conn(1000.0, service="http"))
    assert rec["count"] == 1                  # 2s window: only itself
    assert rec["dst_host_count"] == 31        # host window: all of them
    assert rec["dst_host_srv_count"] == 16    # 15 earlier http + current


def test_port_scan_signature_diff_srv_rate():
    fb = FeatureBuilder()
    services = ["ftp", "ssh", "telnet", "smtp"]
    for i, svc in enumerate(services):
        fb.build(conn(i * 0.1, service=svc, flag="REJ"))
    rec = fb.build(conn(0.5, service="http", flag="REJ"))
    assert rec["diff_srv_rate"] == 0.8
    assert rec["dst_host_diff_srv_rate"] == 0.8
    assert rec["dst_host_same_src_port_rate"] == 1.0
