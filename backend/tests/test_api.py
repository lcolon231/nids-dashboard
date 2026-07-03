"""Tests for the FastAPI app (Phase 7).

Fully synthetic: fake transformer/models are injected into main.STATE, so
these tests pass with or without real artifacts in data/processed/.
"""
from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient

import main
from tests.conftest import make_dataset


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
        main.STATE["transformer"] = FakeTransformer()
        main.STATE["models"] = {
            (m, p): FakeModel(1 if m == "dt" else 0)
            for m in ("nb", "dt")
            for p in ("binary", "multiclass")
        }
        main.STATE["metrics_cache"] = {}

    monkeypatch.setattr(main, "_load_artifacts", fake_load)
    monkeypatch.setattr(main, "ATTACK_LOG_PATH", tmp_path / "attack_log.jsonl")
    main.LIVE_FEED.clear()
    with TestClient(main.app) as c:
        yield c


@pytest.fixture
def empty_client(monkeypatch):
    """TestClient with NO artifacts loaded (503 paths)."""

    def fake_load():
        main.STATE["transformer"] = None
        main.STATE["models"] = {}
        main.STATE["metrics_cache"] = {}

    monkeypatch.setattr(main, "_load_artifacts", fake_load)
    with TestClient(main.app) as c:
        yield c


def records(n: int = 3) -> list[dict]:
    return make_dataset(n).drop(columns=["label"]).to_dict(orient="records")


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
        main.STATE["models"][("dt", "binary")] = FakeModel(0)
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
