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

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from nids.data import CATEGORICAL_COLUMNS, FEATURE_COLUMNS, NUMERIC_COLUMNS

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"
TRANSFORMER_PATH = PROCESSED_DIR / "transformer.joblib"

# --- label maps --------------------------------------------------------------
# Standard NSL-KDD attack -> category mapping (train + test attack names).
ATTACK_CATEGORY = {
    "normal": "normal",
    # dos
    "back": "dos", "land": "dos", "neptune": "dos", "pod": "dos",
    "smurf": "dos", "teardrop": "dos", "apache2": "dos", "udpstorm": "dos",
    "processtable": "dos", "mailbomb": "dos", "worm": "dos",
    # probe
    "satan": "probe", "ipsweep": "probe", "nmap": "probe",
    "portsweep": "probe", "mscan": "probe", "saint": "probe",
    # r2l
    "guess_passwd": "r2l", "ftp_write": "r2l", "imap": "r2l", "phf": "r2l",
    "multihop": "r2l", "warezmaster": "r2l", "warezclient": "r2l",
    "spy": "r2l", "xlock": "r2l", "xsnoop": "r2l", "snmpguess": "r2l",
    "snmpgetattack": "r2l", "httptunnel": "r2l", "sendmail": "r2l",
    "named": "r2l",
    # u2r
    "buffer_overflow": "u2r", "loadmodule": "u2r", "rootkit": "u2r",
    "perl": "u2r", "sqlattack": "u2r", "xterm": "u2r", "ps": "u2r",
}

MULTICLASS_LABELS = ["normal", "dos", "probe", "r2l", "u2r"]
MULTICLASS_TO_INT = {name: i for i, name in enumerate(MULTICLASS_LABELS)}


def binary_labels(labels: pd.Series) -> np.ndarray:
    """Map raw attack labels to binary: normal -> 0, any attack -> 1."""
    return (labels != "normal").astype(int).to_numpy()


def multiclass_labels(labels: pd.Series) -> np.ndarray:
    """Map raw attack labels to ints via the 5 NSL-KDD categories.

    Order: normal=0, dos=1, probe=2, r2l=3, u2r=4.
    Raises on labels missing from ATTACK_CATEGORY so silent mislabeling
    can't slip through.
    """
    unknown = set(labels.unique()) - set(ATTACK_CATEGORY)
    if unknown:
        raise ValueError(f"unknown attack labels: {sorted(unknown)}")
    return labels.map(lambda l: MULTICLASS_TO_INT[ATTACK_CATEGORY[l]]).to_numpy()


# --- feature transformer ------------------------------------------------------
class FeatureTransformer:
    """One-hot encode categoricals + standard-scale numerics for NSL-KDD.

    Fit ONCE on KDDTrain+, then reuse the same fitted instance for the test
    split and live inference. Unknown categories at inference encode to all
    zeros (handle_unknown="ignore") instead of erroring.
    """

    def __init__(self) -> None:
        self._ct = ColumnTransformer(
            transformers=[
                (
                    "cat",
                    OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                    CATEGORICAL_COLUMNS,
                ),
                ("num", StandardScaler(), NUMERIC_COLUMNS),
            ]
        )
        self.fitted = False

    def fit(self, df: pd.DataFrame) -> "FeatureTransformer":
        self._ct.fit(df[FEATURE_COLUMNS])
        self.fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("FeatureTransformer is not fitted — call fit() first")
        return self._ct.transform(df[FEATURE_COLUMNS])

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.fit(df).transform(df)

    @property
    def feature_names(self) -> list[str]:
        """Output column names after one-hot + scaling."""
        if not self.fitted:
            raise RuntimeError("FeatureTransformer is not fitted — call fit() first")
        return list(self._ct.get_feature_names_out())

    # --- persistence ---------------------------------------------------------
    def save(self, path: Path = TRANSFORMER_PATH) -> Path:
        if not self.fitted:
            raise RuntimeError("refusing to save an unfitted transformer")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        print(f"[ok  ] saved transformer -> {path}")
        return path

    @staticmethod
    def load(path: Path = TRANSFORMER_PATH) -> "FeatureTransformer":
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found — run `python -m nids.models train` first"
            )
        return joblib.load(path)
