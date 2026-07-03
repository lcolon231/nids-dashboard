"""Tests for nids.association (Phase 7).

Uses synthetic fixtures only — never loads the full NSL-KDD dataset.
"""
from __future__ import annotations

from nids.association import LABEL_PREFIX, build_transactions, mine_rules


class TestBuildTransactions:
    def test_shape_and_dtype(self, synth_df):
        tx = build_transactions(synth_df)
        assert len(tx) == len(synth_df)
        assert (tx.dtypes == bool).all()

    def test_exactly_one_label_item_per_row(self, synth_df):
        tx = build_transactions(synth_df)
        label_cols = [c for c in tx.columns if c.startswith(LABEL_PREFIX)]
        assert label_cols  # label items present
        assert (tx[label_cols].sum(axis=1) == 1).all()

    def test_item_naming(self, synth_df):
        tx = build_transactions(synth_df)
        assert "protocol_type=tcp" in tx.columns
        assert "label=normal" in tx.columns


class TestMineRules:
    def test_rules_are_pattern_to_class(self, synth_df):
        rules = mine_rules(build_transactions(synth_df))
        assert len(rules) > 0
        # every consequent is a single label item; no label in antecedents
        assert rules["consequents"].str.startswith(LABEL_PREFIX).all()
        assert not rules["antecedents"].str.contains(LABEL_PREFIX, regex=False).any()

    def test_sorted_by_lift_desc(self, synth_df):
        lifts = mine_rules(build_transactions(synth_df))["lift"].tolist()
        assert lifts == sorted(lifts, reverse=True)

    def test_finds_planted_pattern(self, synth_df):
        # conftest gives normal rows flag=SF exclusively, so a confidence-1.0
        # rule flag=SF -> label=normal must surface. (Attack rows split across
        # 4 categories, so no attack-side rule can clear min_confidence=0.7.)
        rules = mine_rules(build_transactions(synth_df))
        sf = rules[rules["antecedents"] == "flag=SF"]
        assert len(sf) == 1
        assert sf.iloc[0]["consequents"] == "label=normal"
        assert sf.iloc[0]["confidence"] == 1.0

    def test_metrics_in_range(self, synth_df):
        rules = mine_rules(build_transactions(synth_df))
        assert rules["support"].between(0, 1).all()
        assert rules["confidence"].between(0.7, 1).all()  # min_confidence=0.7
        assert (rules["lift"] > 0).all()
        assert len(rules) <= 50
