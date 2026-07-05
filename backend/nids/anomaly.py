"""Unsupervised per-source-window anomaly detection (Phase 11).

Unlike the supervised NSL/CIC models — trained on someone else's labeled
attacks — this layer learns what YOUR network's normal per-source windows look
like (nids/windows.py) and flags deviations, with no labels required. It's the
piece that catches scans/floods the per-flow models miss.

Workflow:
  1. Run the backend normally; every finalized window is appended to
     window_baseline.jsonl (the backend does this).
  2. `python -m nids.anomaly train` fits a StandardScaler + IsolationForest on
     that baseline and saves window_anomaly.joblib.
  3. On restart the backend loads it and scores new windows live.

Capture the baseline during NORMAL use only — running attacks during capture
teaches the model that attacks are normal.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from nids.preprocessing import PROCESSED_DIR
from nids.windows import WINDOW_FEATURES

RANDOM_STATE = 42

BASELINE_PATH = PROCESSED_DIR / "window_baseline.jsonl"
ANOMALY_MODEL_PATH = PROCESSED_DIR / "window_anomaly.joblib"

# Expected fraction of baseline windows that are outliers. Kept small: a
# calm home network is mostly benign, so few normal windows should look weird.
CONTAMINATION = 0.02
MIN_BASELINE_WINDOWS = 50


def _to_matrix(windows: list[dict]) -> np.ndarray:
    return np.array([[float(w[f]) for f in WINDOW_FEATURES] for w in windows], dtype=float)


class WindowAnomalyModel:
    """StandardScaler + IsolationForest over the WINDOW_FEATURES vector."""

    def __init__(self) -> None:
        self._scaler = StandardScaler()
        self._iforest = IsolationForest(
            n_estimators=200, contamination=CONTAMINATION, random_state=RANDOM_STATE
        )
        self.fitted = False
        self.n_baseline = 0

    def fit(self, windows: list[dict]) -> "WindowAnomalyModel":
        if len(windows) < MIN_BASELINE_WINDOWS:
            raise ValueError(
                f"need >= {MIN_BASELINE_WINDOWS} baseline windows, got {len(windows)} "
                "— capture more normal traffic first"
            )
        X = self._scaler.fit_transform(_to_matrix(windows))
        self._iforest.fit(X)
        self.fitted = True
        self.n_baseline = len(windows)
        return self

    def score(self, window: dict) -> dict:
        """Score one window. Higher `anomaly_score` = more anomalous;
        `is_anomaly` is IsolationForest's own decision (score < 0)."""
        if not self.fitted:
            raise RuntimeError("WindowAnomalyModel is not fitted — train it first")
        X = self._scaler.transform(_to_matrix([window]))
        # IsolationForest: decision_function > 0 is inlier, < 0 outlier.
        # Flip sign so larger = more anomalous, which reads naturally in a UI.
        raw = float(self._iforest.decision_function(X)[0])
        return {
            "anomaly_score": round(-raw, 4),
            "is_anomaly": bool(self._iforest.predict(X)[0] == -1),
        }

    def save(self, path: Path = ANOMALY_MODEL_PATH) -> Path:
        if not self.fitted:
            raise RuntimeError("refusing to save an unfitted anomaly model")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        print(f"[ok  ] saved anomaly model ({self.n_baseline} baseline windows) -> {path}")
        return path

    @staticmethod
    def load(path: Path = ANOMALY_MODEL_PATH) -> "WindowAnomalyModel":
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found — run `python -m nids.anomaly train` first"
            )
        return joblib.load(path)


def load_baseline(path: Path = BASELINE_PATH) -> list[dict]:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found — run the backend to capture normal windows first"
        )
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def train(baseline_path: Path = BASELINE_PATH, model_path: Path = ANOMALY_MODEL_PATH) -> None:
    windows = load_baseline(baseline_path)
    print(f"[ok  ] loaded {len(windows)} baseline windows from {baseline_path.name}")
    model = WindowAnomalyModel().fit(windows)
    model.save(model_path)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "train"
    if cmd == "train":
        try:
            train(BASELINE_PATH, ANOMALY_MODEL_PATH)
        except (FileNotFoundError, ValueError) as e:
            print(f"[err ] {e}")
            return 1
        return 0
    print(f"unknown command {cmd!r}; usage: python -m nids.anomaly train")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
