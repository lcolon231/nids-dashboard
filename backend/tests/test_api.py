"""Tests for the FastAPI app (Phase 7).

Fully synthetic: fake transformer/models are injected into main.STATE, so
these tests pass with or without real artifacts in data/processed/.
"""
from __future__ import annotations

import json

import numpy as np
import pytest
from fastapi.testclient import TestClient

import main
from tests.conftest import make_cic_dataset, make_dataset


class FakeTransformer:
    fitted = True

    def transform(self, df):
        return np.zeros((len(df), 3))


class FakeModel:
    def __init__(self, value: int = 1):
        self.value = value

    def predict(self, X):
        return np.full(X.shape[0], self.value)


@pytest.fixture
def client(monkeypatch, tmp_path):
    """TestClient with synthetic artifacts injected at startup.

    LIVE_FEED is cleared and the attack log redirected to tmp_path so
    tests never touch data/processed/ and stay independent.
    """

    def fake_load():
        main.STATE["transformers"] = {"nsl": FakeTransformer(), "cic": FakeTransformer()}
        main.STATE["models"] = {
            (d, m, p): FakeModel(1 if m == "dt" else 0)
            for d in ("nsl", "cic")
            for m in ("nb", "dt")
            for p in ("binary", "multiclass")
        }
        main.STATE["metrics_cache"] = {}
        main.STATE["anomaly_model"] = None  # off by default; overridden per-test

    monkeypatch.setattr(main, "_load_artifacts", fake_load)
    monkeypatch.setattr(main, "ATTACK_LOG_PATH", tmp_path / "attack_log.jsonl")
    monkeypatch.setattr(main, "WINDOW_BASELINE_PATH", tmp_path / "window_baseline.jsonl")
    main.LIVE_FEED.clear()
    main.ANOMALY_FEED.clear()
    main.WINDOW_AGGREGATOR.flush_all()
    with TestClient(main.app) as c:
        yield c


@pytest.fixture
def empty_client(monkeypatch):
    """TestClient with NO artifacts loaded (503 paths)."""

    def fake_load():
        main.STATE["transformers"] = {}
        main.STATE["models"] = {}
        main.STATE["metrics_cache"] = {}
        main.STATE["anomaly_model"] = None

    monkeypatch.setattr(main, "_load_artifacts", fake_load)
    with TestClient(main.app) as c:
        yield c


def records(n: int = 3) -> list[dict]:
    return make_dataset(n).drop(columns=["label"]).to_dict(orient="records")


def cic_records(n: int = 3) -> list[dict]:
    return make_cic_dataset(n).drop(columns=["label"]).to_dict(orient="records")


def record_with_files(created: float = 3, accessed: float = 2, root: float = 1) -> dict:
    """One record with explicit file-activity / host-impact values."""
    rec = records(1)[0]
    rec.update(
        num_file_creations=created,
        num_access_files=accessed,
        root_shell=root,
        num_shells=1,
        num_root=2,
        num_compromised=1,
        hot=4,
    )
    return rec


def record_no_files() -> dict:
    rec = records(1)[0]
    rec.update(
        num_file_creations=0,
        num_access_files=0,
        root_shell=0,
        num_shells=0,
        num_root=0,
        num_compromised=0,
        hot=0,
    )
    return rec


class TestHealth:
    def test_ok(self, client):
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["transformer_loaded"] is True
        assert "dt_binary" in body["models_loaded"]

    def test_reports_nothing_loaded(self, empty_client):
        body = empty_client.get("/health").json()
        assert body["models_loaded"] == []
        assert body["transformer_loaded"] is False


class TestPredict:
    def test_dt_binary(self, client):
        r = client.post("/predict?model=dt&phase=binary", json={"records": records(3)})
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 3
        assert all(x["label"] == "attack" and x["is_attack"] for x in body["results"])

    def test_nb_predicts_normal(self, client):
        r = client.post("/predict?model=nb&phase=multiclass", json={"records": records(2)})
        assert all(x["label"] == "normal" and not x["is_attack"] for x in r.json()["results"])

    def test_missing_feature_422(self, client):
        bad = records(1)
        bad[0].pop("duration")
        r = client.post("/predict", json={"records": bad})
        assert r.status_code == 422
        assert "duration" in r.json()["detail"]

    def test_invalid_model_422(self, client):
        r = client.post("/predict?model=svm", json={"records": records(1)})
        assert r.status_code == 422

    def test_empty_records_422(self, client):
        r = client.post("/predict", json={"records": []})
        assert r.status_code == 422

    def test_unloaded_model_503(self, empty_client):
        r = empty_client.post("/predict", json={"records": records(1)})
        assert r.status_code == 503


class TestScoreLive:
    def test_counts_attacks(self, client):
        r = client.post("/score/live", json={"records": records(4)})
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 4
        assert body["attacks"] == 4  # fake dt always predicts 1

    def test_503_when_unloaded(self, empty_client):
        r = empty_client.post("/score/live", json={"records": records(1)})
        assert r.status_code == 503

    def test_events_include_file_activity_fields(self, client):
        client.post(
            "/score/live",
            json={"records": [record_with_files(), record_no_files()]},
        )
        events = client.get("/live/recent").json()["events"]  # newest first
        assert len(events) == 2
        no_files, with_files = events[0], events[1]
        for field in main.FILE_ACTIVITY_FEATURES:
            assert field in with_files and field in no_files
        assert with_files["has_file_activity"] is True
        assert with_files["num_file_creations"] == 3
        assert with_files["num_access_files"] == 2
        assert with_files["root_shell"] == 1
        assert no_files["has_file_activity"] is False


class TestAttackLog:
    def test_empty_when_no_log_file(self, client):
        body = client.get("/attacks/log").json()
        assert body == {"count": 0, "attacks": []}

    def test_attacks_persisted_and_newest_first(self, client):
        client.post("/score/live", json={"records": [record_no_files()]})
        client.post("/score/live", json={"records": [record_with_files()]})

        body = client.get("/attacks/log").json()
        assert body["count"] == 2
        newest, oldest = body["attacks"]
        assert newest["has_file_activity"] is True  # posted last, returned first
        assert oldest["has_file_activity"] is False
        assert newest["is_attack"] is True
        assert "logged_at" in newest  # ISO-8601 UTC timestamp
        assert main.ATTACK_LOG_PATH.exists()  # survives restarts (on disk)

    def test_files_only_filter(self, client):
        client.post(
            "/score/live",
            json={"records": [record_with_files(), record_no_files()]},
        )
        body = client.get("/attacks/log?files_only=true").json()
        assert body["count"] == 1
        assert all(a["has_file_activity"] for a in body["attacks"])

    def test_limit(self, client):
        client.post("/score/live", json={"records": [record_no_files()] * 5})
        body = client.get("/attacks/log?limit=2").json()
        assert body["count"] == 2

    def test_normal_traffic_not_logged(self, client, monkeypatch):
        # make dt predict 0 -> nothing should be appended
        main.STATE["models"][("nsl", "dt", "binary")] = FakeModel(0)
        client.post("/score/live", json={"records": [record_with_files()]})
        assert client.get("/attacks/log").json()["count"] == 0


class TestRules:
    def test_503_when_missing(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(main, "RULES_PATH", tmp_path / "rules.csv")
        assert client.get("/rules").status_code == 503

    def test_top_20_by_lift(self, client, monkeypatch, tmp_path):
        path = tmp_path / "rules.csv"
        lines = ["antecedents,consequents,support,confidence,lift"]
        lines += [f"a{i},label=probe,0.1,0.9,{30 - i}" for i in range(30)]
        path.write_text("\n".join(lines))
        monkeypatch.setattr(main, "RULES_PATH", path)

        body = client.get("/rules").json()
        assert body["count"] == 20
        lifts = [r["lift"] for r in body["rules"]]
        assert lifts == sorted(lifts, reverse=True)


class TestMetricsEndpoint:
    def test_503_when_unloaded(self, empty_client):
        assert empty_client.get("/metrics").status_code == 503


class TestCicDataset:
    def test_predict_multiclass_uses_cic_categories(self, client):
        r = client.post(
            "/predict?model=dt&phase=multiclass&dataset=cic",
            json={"records": cic_records(2)},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["dataset"] == "cic"
        assert all(x["label"] == "dos" for x in body["results"])  # fake dt -> class 1

    def test_predict_missing_cic_feature_422(self, client):
        bad = cic_records(1)
        bad[0].pop("flow_duration")
        r = client.post("/predict?dataset=cic", json={"records": bad})
        assert r.status_code == 422
        assert "flow_duration" in r.json()["detail"]

    def test_nsl_features_rejected_for_cic(self, client):
        r = client.post("/predict?dataset=cic", json={"records": records(1)})
        assert r.status_code == 422

    def test_score_live_cic_keeps_display_metadata(self, client):
        recs = cic_records(2)
        for rec in recs:
            rec.update(protocol_type="tcp", service="http", flag="SF")
        r = client.post("/score/live?dataset=cic", json={"records": recs})
        assert r.status_code == 200
        assert r.json()["attacks"] == 2
        events = client.get("/live/recent?limit=2").json()["events"]
        assert all(e["dataset"] == "cic" and e["service"] == "http" for e in events)

    def test_metrics_served_from_json(self, client, monkeypatch, tmp_path):
        path = tmp_path / "cic_metrics.json"
        fake = {"binary": {"dt": {"accuracy": 0.99, "precision": 1.0, "recall": 0.98, "f1": 0.99}}}
        path.write_text(json.dumps(fake))
        monkeypatch.setattr(main, "CIC_METRICS_PATH", path)
        body = client.get("/metrics?dataset=cic").json()
        assert body["dataset"] == "cic"
        assert body["metrics"]["dt"]["accuracy"] == 0.99

    def test_metrics_503_when_json_missing(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(main, "CIC_METRICS_PATH", tmp_path / "nope.json")
        assert client.get("/metrics?dataset=cic").status_code == 503

    def test_unloaded_cic_model_503(self, empty_client):
        r = empty_client.post("/predict?dataset=cic", json={"records": cic_records(1)})
        assert r.status_code == 503


def cic_records_with_meta(sources_ports) -> list[dict]:
    """CIC records carrying per-source window meta. sources_ports is a list of
    (src_ip, dst_ip, dst_port, flag) tuples."""
    recs = cic_records(len(sources_ports))
    for rec, (src, dst, port, flag) in zip(recs, sources_ports):
        rec["meta"] = {"src_ip": src, "dst_ip": dst, "dst_port": port,
                       "flag": flag, "bytes": 100}
    return recs


class TestAnomalyEndpoints:
    def test_status_reports_no_model_and_baseline_growth(self, client):
        body = client.get("/anomalies/status").json()
        assert body["model_loaded"] is False
        assert body["baseline_windows_captured"] == 0
        assert body["window_seconds"] == main.WINDOW_SECONDS

    def test_windowing_captures_baseline_when_windows_close(self, client):
        # window 1: flows at ts within [0,60); window 2 at ts>=60 closes it.
        early = cic_records_with_meta([("A", "X", 80, "SF")])
        early[0]["meta"]["ts"] = 10
        # Post early flows (they land in the current wall-clock window), then a
        # later post advances time. We drive time via the aggregator directly
        # to make the test deterministic.
        main.WINDOW_AGGREGATOR.add({"src_ip": "A", "dst_ip": "X", "dst_port": 80,
                                    "flag": "SF", "bytes": 100}, ts=10)
        main.WINDOW_AGGREGATOR.add({"src_ip": "A", "dst_ip": "X", "dst_port": 81,
                                    "flag": "SF", "bytes": 100}, ts=20)
        main._process_finalized_windows(now=200)  # closes the [0,60) window
        status = client.get("/anomalies/status").json()
        assert status["baseline_windows_captured"] == 1
        # no model -> nothing scored into the anomaly feed
        assert client.get("/anomalies/recent").json()["count"] == 0

    def test_recent_scores_windows_when_model_loaded(self, client):
        # Inject a fake anomaly model that flags any window with a big fan-out.
        class FakeAnomaly:
            def score(self, w):
                hot = w["distinct_dst_ports"] > 50
                return {"anomaly_score": 9.9 if hot else 0.1, "is_anomaly": hot}

        main.STATE["anomaly_model"] = FakeAnomaly()
        # a scan window: one source, 100 ports
        for port in range(100):
            main.WINDOW_AGGREGATOR.add(
                {"src_ip": "scanner", "dst_ip": "victim", "dst_port": port,
                 "flag": "S0", "bytes": 0}, ts=5)
        # a benign window from another source
        main.WINDOW_AGGREGATOR.add(
            {"src_ip": "user", "dst_ip": "web", "dst_port": 443,
             "flag": "SF", "bytes": 5000}, ts=5)
        main._process_finalized_windows(now=200)

        body = client.get("/anomalies/recent").json()
        assert body["count"] == 2
        assert body["anomalies"] == 1
        scanner = [w for w in body["windows"] if w["src_ip"] == "scanner"][0]
        assert scanner["is_anomaly"] is True
        assert scanner["distinct_dst_ports"] == 100

    def test_anomalies_only_filter(self, client):
        class FakeAnomaly:
            def score(self, w):
                hot = w["src_ip"] == "bad"
                return {"anomaly_score": 5.0 if hot else 0.0, "is_anomaly": hot}

        main.STATE["anomaly_model"] = FakeAnomaly()
        for src in ("good", "bad"):
            main.WINDOW_AGGREGATOR.add(
                {"src_ip": src, "dst_ip": "h", "dst_port": 1, "flag": "SF", "bytes": 1}, ts=5)
        main._process_finalized_windows(now=200)
        body = client.get("/anomalies/recent?anomalies_only=true").json()
        assert body["count"] == 1
        assert body["windows"][0]["src_ip"] == "bad"

    def test_score_live_feeds_windowing_via_meta(self, client):
        recs = cic_records_with_meta([("10.0.0.9", "8.8.8.8", 53, "SF")])
        r = client.post("/score/live?dataset=cic", json={"records": recs})
        assert r.status_code == 200
        # the flow's meta opened a per-source window
        assert client.get("/anomalies/status").json()["windows_open"] >= 1


class TestAlertEndpoints:
    def test_status_disabled_by_default(self, client):
        body = client.get("/alerts/status").json()
        assert body["enabled"] is False
        assert body["kind"] == "ntfy"

    def test_test_endpoint_503_when_unconfigured(self, client):
        assert client.post("/alerts/test").status_code == 503

    def test_test_endpoint_sends_when_configured(self, client, monkeypatch):
        from nids.alerts import AlertConfig, AlertNotifier

        sent = []
        cfg = AlertConfig(kind="generic", webhook_url="http://hook.test")
        monkeypatch.setattr(main, "NOTIFIER", AlertNotifier(cfg, sender=lambda t, m: sent.append(m)))
        body = client.post("/alerts/test").json()
        assert body["sent"] is True
        assert len(sent) == 1

    def test_score_live_triggers_alert_over_threshold(self, client, monkeypatch):
        from nids.alerts import AlertConfig, AlertNotifier

        sent = []
        cfg = AlertConfig(kind="generic", webhook_url="http://hook.test",
                          min_attacks=3, cooldown=0)
        monkeypatch.setattr(main, "NOTIFIER", AlertNotifier(cfg, sender=lambda t, m: sent.append(m)))
        # fake dt flags every record as attack; 4 records >= min_attacks 3
        recs = cic_records_with_meta([("bad", "v", p, "S0") for p in range(4)])
        client.post("/score/live?dataset=cic", json={"records": recs})
        assert len(sent) == 1
        assert "bad" in sent[0]


class TestApiKeyAuth:
    def test_open_when_unset(self, client):
        # default API_KEY is None -> no auth required
        assert client.get("/live/recent").status_code == 200

    def test_401_without_key_when_set(self, client, monkeypatch):
        monkeypatch.setattr(main, "API_KEY", "s3cret")
        assert client.get("/live/recent").status_code == 401
        assert client.post("/predict", json={"records": records(1)}).status_code == 401

    def test_200_with_correct_key(self, client, monkeypatch):
        monkeypatch.setattr(main, "API_KEY", "s3cret")
        r = client.post(
            "/predict", json={"records": records(1)}, headers={"X-API-Key": "s3cret"}
        )
        assert r.status_code == 200

    def test_wrong_key_rejected(self, client, monkeypatch):
        monkeypatch.setattr(main, "API_KEY", "s3cret")
        r = client.get("/live/recent", headers={"X-API-Key": "nope"})
        assert r.status_code == 401

    def test_health_exempt_even_when_key_set(self, client, monkeypatch):
        monkeypatch.setattr(main, "API_KEY", "s3cret")
        assert client.get("/health").status_code == 200


class TestInputLimits:
    def test_too_many_records_422(self, client):
        r = client.post("/predict", json={"records": [{}] * (main.MAX_RECORDS + 1)})
        assert r.status_code == 422

    def test_junk_keys_ignored_not_expanded(self, client):
        rec = cic_records(1)[0]
        rec.update({f"junk_{i}": i for i in range(200)})  # attacker-supplied noise
        r = client.post("/predict?dataset=cic", json={"records": [rec]})
        assert r.status_code == 200
        assert r.json()["count"] == 1


class TestLogRotation:
    def test_append_jsonl_rotates_and_keeps_tail(self, tmp_path, monkeypatch):
        path = tmp_path / "log.jsonl"
        monkeypatch.setattr(main, "MAX_LOG_BYTES", 200)
        monkeypatch.setattr(main, "KEEP_LINES", 5)
        for i in range(100):
            main._append_jsonl(path, {"i": i})
        lines = path.read_text().splitlines()
        # disk stays bounded by the byte cap (didn't grow to all 100 lines)
        assert path.stat().st_size <= main.MAX_LOG_BYTES + 64
        assert len(lines) < 100
        assert json.loads(lines[-1])["i"] == 99  # newest survives the rotation
