"""Tests for nids.models + nids.evaluation (Phase 7).

Uses synthetic fixtures only. Model artifacts are redirected to tmp_path
so tests never touch data/processed/.
"""
from __future__ import annotations

import json

import joblib
import numpy as np
import pytest

from nids import models
from nids.evaluation import metrics
from nids.preprocessing import FeatureTransformer


@pytest.fixture
def patched_paths(tmp_path, monkeypatch):
    """Redirect every artifact path in nids.models into tmp_path."""
    monkeypatch.setattr(models, "PROCESSED_DIR", tmp_path)
    monkeypatch.setattr(models, "KMEANS_PATH", tmp_path / "kmeans.joblib")
    monkeypatch.setattr(models, "KMEANS_SWEEP_PATH", tmp_path / "kmeans_sweep.json")
    return tmp_path


class TestMetrics:
    def test_perfect_binary(self):
        y = np.array([0, 1, 0, 1])
        m = metrics(y, y, "binary")
        assert m == {"accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1": 1.0}

    def test_binary_values(self):
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([0, 1, 1, 1])
        m = metrics(y_true, y_pred, "binary")
        assert m["accuracy"] == 0.75
        assert m["precision"] == pytest.approx(2 / 3)
        assert m["recall"] == 1.0

    def test_multiclass_macro(self):
        y_true = np.array([0, 1, 2, 0, 1, 2])
        y_pred = np.array([0, 1, 2, 0, 1, 0])
        m = metrics(y_true, y_pred, "multiclass")
        assert 0 < m["f1"] < 1
        assert all(isinstance(v, float) for v in m.values())

    def test_bad_phase_raises(self):
        with pytest.raises(ValueError, match="unknown phase"):
            metrics(np.array([0]), np.array([0]), "ternary")


class TestModelPath:
    def test_valid(self):
        assert models.model_path("nb", "binary").name == "nb_binary.joblib"

    def test_bad_model(self):
        with pytest.raises(ValueError, match="unknown model"):
            models.model_path("svm", "binary")

    def test_bad_phase(self):
        with pytest.raises(ValueError, match="unknown phase"):
            models.model_path("dt", "ternary")


class TestTrainClassifiers:
    def test_trains_persists_and_scores(self, synth_split, patched_paths):
        train, test = synth_split
        t = FeatureTransformer().fit(train)
        results = models.train_classifiers(
            t.transform(train), train["label"], t.transform(test), test["label"]
        )
        # 4 artifacts on disk
        for model in models.MODEL_NAMES:
            for phase in models.PHASES:
                path = patched_paths / f"{model}_{phase}.joblib"
                assert path.exists()
                assert hasattr(joblib.load(path), "predict")
        # synthetic data is highly separable -> strong binary accuracy
        assert results["binary"]["dt"]["accuracy"] > 0.9
        assert set(results["binary"]["nb"]) == {"accuracy", "precision", "recall", "f1"}


class TestKMeansSweep:
    def test_sweep_picks_best_k(self, patched_paths, monkeypatch):
        monkeypatch.setattr(models, "KMEANS_SAMPLE", 60)
        monkeypatch.setattr(models, "KMEANS_K_RANGE", range(2, 5))
        # 3 well-separated blobs -> silhouette should peak at k=3
        rng = np.random.RandomState(0)
        X = np.vstack([rng.randn(40, 5) + c * 10 for c in range(3)])

        result = models.kmeans_sweep(X)

        assert result["best_k"] == 3
        assert [r["k"] for r in result["sweep"]] == [2, 3, 4]
        assert (patched_paths / "kmeans.joblib").exists()
        saved = json.loads((patched_paths / "kmeans_sweep.json").read_text())
        assert saved["best_k"] == 3
        # inertia decreases monotonically with k
        inertias = [r["inertia"] for r in result["sweep"]]
        assert inertias == sorted(inertias, reverse=True)
