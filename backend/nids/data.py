"""NSL-KDD dataset download + verification.

The NSL-KDD files have no header row. Each line is 41 KDD Cup '99 features,
then the attack label (col 42), then a difficulty score (col 43). We assign
the standard column names, drop the difficulty column on load, and keep the
label.

CLI:
    python -m nids.data download
"""
from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

import pandas as pd

# --- paths -----------------------------------------------------------------
BACKEND_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BACKEND_DIR / "data" / "raw"

SPLITS = {
    "train": {
        "filename": "KDDTrain+.txt",
        "url": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt",
        "rows": 125_973,
    },
    "test": {
        "filename": "KDDTest+.txt",
        "url": "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt",
        "rows": 22_544,
    },
}

# Standard KDD Cup '99 / NSL-KDD column names: 41 features + label + difficulty.
FEATURE_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
assert len(FEATURE_COLUMNS) == 41

# All 43 raw columns, in order.
ALL_COLUMNS = FEATURE_COLUMNS + ["label", "difficulty"]

# Categorical features that need one-hot encoding downstream.
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]
NUMERIC_COLUMNS = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLUMNS]


def download(force: bool = False) -> None:
    """Download both NSL-KDD splits into data/raw/, then verify."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for split, meta in SPLITS.items():
        dest = RAW_DIR / meta["filename"]
        if dest.exists() and not force:
            print(f"[skip] {dest} already exists")
        else:
            print(f"[get ] {meta['url']} -> {dest}")
            urllib.request.urlretrieve(meta["url"], dest)
        verify(split)


def load(split: str, drop_difficulty: bool = True) -> pd.DataFrame:
    """Load a split as a DataFrame with named columns.

    Drops the difficulty column by default (keeps 41 features + label).
    """
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; expected one of {list(SPLITS)}")
    path = RAW_DIR / SPLITS[split]["filename"]
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found — run `python -m nids.data download` first"
        )
    df = pd.read_csv(path, header=None, names=ALL_COLUMNS)
    if drop_difficulty:
        df = df.drop(columns=["difficulty"])
    return df


def verify(split: str) -> pd.DataFrame:
    """Assert the raw split has the exact expected shape (rows x 43 cols)."""
    df = load(split, drop_difficulty=False)
    expected_rows = SPLITS[split]["rows"]
    rows, cols = df.shape
    if rows != expected_rows or cols != 43:
        raise ValueError(
            f"{split}: expected {expected_rows} rows x 43 cols, got {rows} x {cols}"
        )
    print(f"[ok  ] {split}: {rows} rows x {cols} cols")
    return df


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "download"
    if cmd == "download":
        download(force="--force" in argv)
        return 0
    print(f"unknown command {cmd!r}; usage: python -m nids.data download [--force]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
