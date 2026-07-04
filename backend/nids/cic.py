"""CIC-IDS2017 download, cleaning, splitting, and scaling.

The dataset ships as 8 per-day CSVs of CICFlowMeter features (~2.8M flows,
Monday is all-benign). We keep only the 32 FLOW_FEATURES the Pi sensor can
compute live (see nids/flowschema.py) plus the label.

CLI:
    python -m nids.cic download      # fetch + extract MachineLearningCSV.zip
"""
from __future__ import annotations

import sys
import urllib.request
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

from nids.data import RAW_DIR
from nids.flowschema import (
    CIC_CATEGORY_TO_INT,
    CIC_COLUMN_MAP,
    FLOW_FEATURES,
    cic_category,
)
from nids.preprocessing import PROCESSED_DIR

CIC_DIR = RAW_DIR / "cic"
CIC_ZIP_URL = "http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/MachineLearningCSV.zip"
CIC_TRANSFORMER_PATH = PROCESSED_DIR / "cic_transformer.joblib"

RANDOM_STATE = 42
TEST_SIZE = 0.3


def download(force: bool = False) -> None:
    """Fetch + extract the MachineLearningCSV zip into data/raw/cic/.

    If the UNB mirror is unreachable, download MachineLearningCSV.zip
    manually (https://www.unb.ca/cic/datasets/ids-2017.html) and unzip the
    CSVs into data/raw/cic/ yourself.
    """
    CIC_DIR.mkdir(parents=True, exist_ok=True)
    if list(CIC_DIR.glob("**/*.csv")) and not force:
        print(f"[skip] {CIC_DIR} already has CSVs")
        return
    dest = CIC_DIR / "MachineLearningCSV.zip"
    print(f"[get ] {CIC_ZIP_URL} -> {dest} (~230 MB)")
    urllib.request.urlretrieve(CIC_ZIP_URL, dest)
    with zipfile.ZipFile(dest) as zf:
        zf.extractall(CIC_DIR)
    dest.unlink()
    print(f"[ok  ] extracted {len(list(CIC_DIR.glob('**/*.csv')))} CSVs -> {CIC_DIR}")


def load() -> pd.DataFrame:
    """All days combined, cleaned: FLOW_FEATURES + raw string `label`.

    Cleaning: strip column whitespace, keep only mapped columns, coerce to
    numeric, drop rows with NaN/Inf (CIC's Flow Bytes/s has both) or
    negative durations.
    """
    paths = sorted(CIC_DIR.glob("**/*.csv"))
    if not paths:
        raise FileNotFoundError(
            f"no CSVs under {CIC_DIR} — run `python -m nids.cic download` first"
        )
    frames = []
    for path in paths:
        df = pd.read_csv(path, encoding="latin1", skipinitialspace=True)
        df.columns = [c.strip() for c in df.columns]
        cols = {ours: df[theirs] for ours, theirs in CIC_COLUMN_MAP.items()}
        out = pd.DataFrame(cols)
        out = out.apply(pd.to_numeric, errors="coerce")
        out["label"] = df["Label"].astype(str).str.strip()
        out = out.replace([np.inf, -np.inf], np.nan).dropna()
        out = out[out["flow_duration"] >= 0]
        frames.append(out)
        print(f"[ok  ] {path.name}: {len(out)} rows after cleaning")
    combined = pd.concat(frames, ignore_index=True)
    print(f"[ok  ] CIC-IDS2017 combined: {len(combined)} rows")
    return combined


# --- labels -------------------------------------------------------------------
def binary_labels(labels: pd.Series) -> np.ndarray:
    """BENIGN -> 0, any attack -> 1."""
    return (labels.str.strip() != "BENIGN").astype(int).to_numpy()


def multiclass_labels(labels: pd.Series) -> np.ndarray:
    """Raw CIC labels -> ints via the 7 categories in flowschema."""
    return labels.map(lambda l: CIC_CATEGORY_TO_INT[cic_category(l)]).to_numpy()


def split(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stratified 70/30 train/test split (CIC has no canonical split)."""
    strata = multiclass_labels(df["label"])
    train_df, test_df = train_test_split(
        df, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=strata
    )
    return train_df, test_df


# --- transformer ---------------------------------------------------------------
class FlowTransformer:
    """StandardScaler over the 32 numeric flow features (no categoricals)."""

    def __init__(self) -> None:
        self._scaler = StandardScaler()
        self.fitted = False

    def fit(self, df: pd.DataFrame) -> "FlowTransformer":
        self._scaler.fit(df[FLOW_FEATURES])
        self.fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        if not self.fitted:
            raise RuntimeError("FlowTransformer is not fitted — call fit() first")
        return self._scaler.transform(df[FLOW_FEATURES])

    def save(self, path: Path = CIC_TRANSFORMER_PATH) -> Path:
        if not self.fitted:
            raise RuntimeError("refusing to save an unfitted transformer")
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        print(f"[ok  ] saved CIC transformer -> {path}")
        return path

    @staticmethod
    def load(path: Path = CIC_TRANSFORMER_PATH) -> "FlowTransformer":
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found — run `python -m nids.models train --dataset cic` first"
            )
        return joblib.load(path)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "download"
    if cmd == "download":
        download(force="--force" in argv)
        return 0
    print(f"unknown command {cmd!r}; usage: python -m nids.cic download [--force]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
