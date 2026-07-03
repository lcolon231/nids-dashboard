"""Classification metrics for NSL-KDD models.

Phase 4/6 implements:
  - metrics(y_true, y_pred): accuracy, precision, recall, f1
    (binary: average='binary'; multiclass: average='macro')
"""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)


def metrics(y_true: np.ndarray, y_pred: np.ndarray, phase: str = "binary") -> dict:
    """Compute accuracy/precision/recall/f1 as plain floats (JSON-safe).

    phase="binary" uses average='binary'; "multiclass" uses macro averaging.
    """
    if phase not in ("binary", "multiclass"):
        raise ValueError(f"unknown phase {phase!r}; expected 'binary' or 'multiclass'")
    average = "binary" if phase == "binary" else "macro"
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, average=average, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, average=average, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, average=average, zero_division=0)),
    }
