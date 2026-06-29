"""Feature preprocessing for NSL-KDD.

Phase 3 implements FeatureTransformer:
  - one-hot encode protocol_type, service, flag
  - StandardScaler on numeric features
  - fit/transform + persist to data/processed/transformer.joblib
  - SAME fitted transformer reused at inference (no refit -> no drift)

Label maps:
  - binary: "normal" -> 0, else -> 1
  - multiclass: normal, dos, probe, r2l, u2r
"""
from __future__ import annotations

# Implemented in Phase 3.
