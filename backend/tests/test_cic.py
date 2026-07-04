"""Tests for nids.cic + nids.flowschema (Phase 10).

Synthetic only: loader tests write tiny CSVs with real CIC column names
(including their leading-space quirk) into tmp_path.
"""
from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
import pytest

from nids import cic, models
from nids.flowschema import CIC_CATEGORIES, CIC_COLUMN_MAP, FLOW_FEATURES, cic_category
from tests.conftest import make_cic_dataset


def write_cic_csv(path, rows):
    """CSV with CIC's real header style (leading spaces on most columns)."""
    header = ["Destination Port"] + [
        f" {name}" for name in list(CIC_COLUMN_MAP.values())[1:]
    ] + [" Label"]
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join(str(v) for v in row))
    path.write_text("\n".join(lines), encoding="latin1")


def make_row(label="BENIGN", duration=1000, flow_bytes="500.0"):
    values = []
    for name in FLOW_FEATURES:
        if name == "flow_duration":
            values.append(duration)
        elif name == "flow_bytes_per_s":
            values.append(flow_bytes)
        else:
            values.append(1)
    return values + [label]


class TestSchema:
    def test_32_features(self):
        assert len(FLOW_FEATURES) == 32
        assert len(set(FLOW_FEATURES)) == 32

    def test_category_map(self):
        assert cic_category("BENIGN") == "benign"
        assert cic_category("DoS Hulk") == "dos"
        assert cic_category("PortScan") == "portscan"
        assert cic_category("FTP-Patator") == "bruteforce"
        assert cic_category("Web Attack � Brute Force") == "webattack"
        assert cic_category("Heartbleed") == "other"

    def test_unknown_label_raises(self):
        with pytest.raises(ValueError, match="unknown CIC-IDS2017 label"):
            cic_category("Zero Day")


class TestLoad:
    def test_missing_dir_raises(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cic, "CIC_DIR", tmp_path / "empty")
        with pytest.raises(FileNotFoundError, match="python -m nids.cic download"):
            cic.load()

    def test_loads_renames_and_cleans(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cic, "CIC_DIR", tmp_path)
        write_cic_csv(
            tmp_path / "monday.csv",
            [
                make_row("BENIGN"),
                make_row("DoS Hulk"),
                make_row("BENIGN", flow_bytes="Infinity"),  # inf -> dropped
                make_row("BENIGN", duration=-1),  # negative duration -> dropped
            ],
        )
        df = cic.load()
        assert list(df.columns) == FLOW_FEATURES + ["label"]
        assert len(df) == 2
        assert set(df["label"]) == {"BENIGN", "DoS Hulk"}

    def test_combines_multiple_days(self, tmp_path, monkeypatch):
        monkeypatch.setattr(cic, "CIC_DIR", tmp_path)
        write_cic_csv(tmp_path / "mon.csv", [make_row("BENIGN")])
        write_cic_csv(tmp_path / "tue.csv", [make_row("PortScan")] * 2)
        assert len(cic.load()) == 3


class TestLabels:
    def test_binary(self):
        labels = pd.Series(["BENIGN", "DoS Hulk", " BENIGN ", "PortScan"])
        assert cic.binary_labels(labels).tolist() == [0, 1, 0, 1]

    def test_multiclass(self):
        labels = pd.Series(["BENIGN", "DDoS", "PortScan", "Bot"])
        y = cic.multiclass_labels(labels)
        assert [CIC_CATEGORIES[i] for i in y] == ["benign", "dos", "portscan", "botnet"]


class TestSplit:
    def test_stratified_70_30(self):
        df = make_cic_dataset(200)
        train_df, test_df = cic.split(df)
        assert len(train_df) + len(test_df) == 200
        assert len(test_df) == 60
        # both splits keep both classes
        assert set(cic.binary_labels(train_df["label"])) == {0, 1}
        assert set(cic.binary_labels(test_df["label"])) == {0, 1}


class TestFlowTransformer:
    def test_fit_transform_shape_and_scaling(self):
        df = make_cic_dataset(100)
        t = cic.FlowTransformer().fit(df)
        X = t.transform(df)
        assert X.shape == (100, 32)
        assert abs(X.mean()) < 0.1  # standardized

    def test_unfitted_raises(self):
        with pytest.raises(RuntimeError, match="not fitted"):
            cic.FlowTransformer().transform(make_cic_dataset(5))

    def test_save_load_roundtrip(self, tmp_path):
        df = make_cic_dataset(50)
        t = cic.FlowTransformer().fit(df)
        path = t.save(tmp_path / "cic_transformer.joblib")
        loaded = cic.FlowTransformer.load(path)
        assert np.allclose(loaded.transform(df), t.transform(df))

    def test_load_missing_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="--dataset cic"):
            cic.FlowTransformer.load(tmp_path / "nope.joblib")


class TestCicModelPath:
    def test_cic_prefix(self):
        assert models.model_path("dt", "binary", "cic").name == "cic_dt_binary.joblib"
        assert models.model_path("dt", "binary", "nsl").name == "dt_binary.joblib"

    def test_bad_dataset(self):
        with pytest.raises(ValueError, match="unknown dataset"):
            models.model_path("dt", "binary", "kitsune")


class TestTrainCicClassifiers:
    def test_trains_persists_and_scores(self, tmp_path, monkeypatch):
        monkeypatch.setattr(models, "PROCESSED_DIR", tmp_path)
        train_df = make_cic_dataset(300, seed=1)
        test_df = make_cic_dataset(100, seed=2)
        t = cic.FlowTransformer().fit(train_df)
        results = models.train_classifiers(
            t.transform(train_df),
            train_df["label"],
            t.transform(test_df),
            test_df["label"],
            dataset="cic",
        )
        for model in models.MODEL_NAMES:
            for phase in models.PHASES:
                path = tmp_path / f"cic_{model}_{phase}.joblib"
                assert path.exists()
                assert hasattr(joblib.load(path), "predict")
        assert results["binary"]["dt"]["accuracy"] > 0.9
