"""Window anomaly model: fit / score / persist / train CLI (Phase 11)."""
import json

import numpy as np
import pytest

from nids import anomaly
from nids.anomaly import WindowAnomalyModel, load_baseline, train
from nids.windows import WINDOW_FEATURES


def normal_window(seed_rng, i):
    """A calm per-source window: 1-3 flows, one host, established, small."""
    return {
        "src_ip": f"10.0.0.{i % 50}",
        "window_start": float(i * 60),
        "flow_count": int(seed_rng.integers(1, 4)),
        "distinct_dst_ports": int(seed_rng.integers(1, 3)),
        "distinct_dst_hosts": 1,
        "failed_ratio": 0.0,
        "ports_per_host": 1.0,
        "total_bytes": float(seed_rng.integers(1000, 8000)),
        "mean_bytes": float(seed_rng.integers(500, 4000)),
    }


def scan_window():
    """A port scan: huge fan-out, all failed, no bytes."""
    return {
        "src_ip": "10.0.0.66",
        "window_start": 9000.0,
        "flow_count": 999,
        "distinct_dst_ports": 999,
        "distinct_dst_hosts": 1,
        "failed_ratio": 1.0,
        "ports_per_host": 999.0,
        "total_bytes": 0.0,
        "mean_bytes": 0.0,
    }


@pytest.fixture
def baseline():
    rng = np.random.default_rng(0)
    return [normal_window(rng, i) for i in range(200)]


class TestFitScore:
    def test_requires_minimum_baseline(self):
        with pytest.raises(ValueError, match="need >="):
            WindowAnomalyModel().fit([normal_window(np.random.default_rng(0), 0)] * 10)

    def test_flags_scan_not_normal(self, baseline):
        model = WindowAnomalyModel().fit(baseline)
        rng = np.random.default_rng(1)
        normal = model.score(normal_window(rng, 7))
        scan = model.score(scan_window())
        assert scan["is_anomaly"] is True
        assert normal["is_anomaly"] is False
        # the scan should score far more anomalous than a normal window
        assert scan["anomaly_score"] > normal["anomaly_score"]

    def test_score_keys(self, baseline):
        model = WindowAnomalyModel().fit(baseline)
        s = model.score(scan_window())
        assert set(s) == {"anomaly_score", "is_anomaly"}

    def test_unfitted_raises(self):
        with pytest.raises(RuntimeError, match="not fitted"):
            WindowAnomalyModel().score(scan_window())


class TestPersistence:
    def test_save_load_roundtrip(self, baseline, tmp_path):
        model = WindowAnomalyModel().fit(baseline)
        path = model.save(tmp_path / "anomaly.joblib")
        loaded = WindowAnomalyModel.load(path)
        assert loaded.n_baseline == 200
        assert loaded.score(scan_window()) == model.score(scan_window())

    def test_load_missing_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="python -m nids.anomaly train"):
            WindowAnomalyModel.load(tmp_path / "nope.joblib")

    def test_refuse_save_unfitted(self, tmp_path):
        with pytest.raises(RuntimeError, match="unfitted"):
            WindowAnomalyModel().save(tmp_path / "x.joblib")


class TestTrainCLI:
    def test_train_reads_baseline_and_saves(self, baseline, tmp_path):
        bpath = tmp_path / "window_baseline.jsonl"
        bpath.write_text("\n".join(json.dumps(w) for w in baseline))
        mpath = tmp_path / "window_anomaly.joblib"
        train(baseline_path=bpath, model_path=mpath)
        assert mpath.exists()
        assert WindowAnomalyModel.load(mpath).score(scan_window())["is_anomaly"] is True

    def test_load_baseline_missing(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="capture normal windows"):
            load_baseline(tmp_path / "none.jsonl")

    def test_main_returns_1_without_baseline(self, tmp_path, monkeypatch):
        monkeypatch.setattr(anomaly, "BASELINE_PATH", tmp_path / "none.jsonl")
        assert anomaly.main([]) == 1

    def test_feature_order_matches_windows_module(self):
        assert WINDOW_FEATURES == [
            "flow_count", "distinct_dst_ports", "distinct_dst_hosts",
            "failed_ratio", "ports_per_host", "total_bytes", "mean_bytes",
        ]
