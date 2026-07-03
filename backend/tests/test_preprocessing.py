"""Tests for nids.preprocessing (Phase 7).

Uses synthetic fixtures only — never loads the full NSL-KDD dataset.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from nids.data import NUMERIC_COLUMNS
from nids.preprocessing import (
    FeatureTransformer,
    MULTICLASS_LABELS,
    binary_labels,
    multiclass_labels,
)
from tests.conftest import make_dataset


class TestFeatureTransformer:
    def test_fit_transform_shape(self, synth_df):
        t = FeatureTransformer()
        X = t.fit_transform(synth_df)
        assert X.shape[0] == len(synth_df)
        # one-hot columns + all numeric columns
        n_onehot = sum(synth_df[c].nunique() for c in ("protocol_type", "service", "flag"))
        assert X.shape[1] == n_onehot + len(NUMERIC_COLUMNS)

    def test_numeric_scaling(self, synth_df):
        X = FeatureTransformer().fit_transform(synth_df)
        num = X[:, -len(NUMERIC_COLUMNS):]
        assert abs(num.mean()) < 1e-9
        # constant columns scale to 0-std; check the non-constant ones
        stds = num.std(axis=0)
        assert np.allclose(stds[stds > 0], 1.0, atol=1e-9)

    def test_transform_before_fit_raises(self, synth_df):
        with pytest.raises(RuntimeError, match="not fitted"):
            FeatureTransformer().transform(synth_df)

    def test_unknown_category_encodes_to_zeros(self, synth_df):
        t = FeatureTransformer().fit(synth_df)
        oddball = synth_df.head(1).copy()
        oddball["service"] = "never_seen_service"
        X = t.transform(oddball)  # must not raise
        service_cols = [i for i, n in enumerate(t.feature_names) if n.startswith("cat__service")]
        assert X[0, service_cols].sum() == 0

    def test_same_width_across_splits(self, synth_split):
        train, test = synth_split
        t = FeatureTransformer().fit(train)
        assert t.transform(train).shape[1] == t.transform(test).shape[1]

    def test_save_load_roundtrip(self, synth_df, tmp_path):
        t = FeatureTransformer().fit(synth_df)
        path = t.save(tmp_path / "transformer.joblib")
        t2 = FeatureTransformer.load(path)
        assert np.array_equal(t.transform(synth_df), t2.transform(synth_df))

    def test_save_unfitted_raises(self, tmp_path):
        with pytest.raises(RuntimeError, match="unfitted"):
            FeatureTransformer().save(tmp_path / "t.joblib")

    def test_load_missing_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            FeatureTransformer.load(tmp_path / "nope.joblib")


class TestLabelMaps:
    def test_binary(self):
        labels = pd.Series(["normal", "neptune", "normal", "rootkit"])
        assert binary_labels(labels).tolist() == [0, 1, 0, 1]

    def test_multiclass_categories(self):
        labels = pd.Series(["normal", "neptune", "satan", "guess_passwd", "rootkit"])
        got = multiclass_labels(labels)
        names = [MULTICLASS_LABELS[i] for i in got]
        assert names == ["normal", "dos", "probe", "r2l", "u2r"]

    def test_unknown_label_raises(self):
        with pytest.raises(ValueError, match="unknown attack labels"):
            multiclass_labels(pd.Series(["normal", "made_up_attack"]))

    def test_synthetic_dataset_covers_all_classes(self):
        df = make_dataset(500)
        assert set(multiclass_labels(df["label"])) == set(range(5))
