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
def client(monkeypatch):
    """TestClient with synthetic artifacts injected at startup."""

    def fake_load():
        main.STATE["transformer"] = FakeTransformer()
        main.STATE["models"] = {
            (m, p): FakeModel(1 if m == "dt" else 0)
            for m in ("nb", "dt")
            for p in ("binary", "multiclass")
        }
        main.STATE["metrics_cache"] = {}

    monkeypatch.setattr(main, "_load_artifacts", fake_load)
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
