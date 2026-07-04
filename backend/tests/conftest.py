"""Shared synthetic fixtures for the NIDS test suite (Phase 7).

Never loads the real NSL-KDD dataset — every test runs on a small
generated DataFrame with the same 41-feature + label schema.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from nids.data import CATEGORICAL_COLUMNS, FEATURE_COLUMNS

# Small category vocabularies mirroring real NSL-KDD values.
CATEGORY_VALUES = {
    "protocol_type": ["tcp", "udp", "icmp"],
    "service": ["http", "private", "ftp_data", "smtp"],
    "flag": ["SF", "S0", "REJ", "RSTR"],
}

# One label per multiclass category so label maps are fully exercised.
LABELS = ["normal", "neptune", "satan", "guess_passwd", "rootkit"]


def make_dataset(n: int = 200, seed: int = 0) -> pd.DataFrame:
    """Synthetic NSL-KDD-shaped frame: 41 features + label.

    Rows are drawn so that categorical values correlate with the label
    (attacks skew toward flag=S0/RSTR + service=private), giving models
    and rule mining real signal to find.
    """
    rng = np.random.RandomState(seed)
    is_attack = rng.rand(n) < 0.5

    df = pd.DataFrame(index=range(n))
    for col in FEATURE_COLUMNS:
        if col in CATEGORICAL_COLUMNS:
            continue
        # numeric signal: attacks have larger values on a few key columns
        base = rng.rand(n)
        if col in ("count", "srv_count", "serror_rate"):
            base = base + is_attack * 2.0
        df[col] = base

    df["protocol_type"] = np.where(is_attack, "tcp", rng.choice(["udp", "icmp"], n))
    df["service"] = np.where(is_attack, "private", rng.choice(["http", "smtp"], n))
    df["flag"] = np.where(is_attack, rng.choice(["S0", "RSTR"], n), "SF")
    df["label"] = np.where(is_attack, rng.choice(LABELS[1:], n), "normal")
    return df[FEATURE_COLUMNS + ["label"]]


def make_cic_dataset(n: int = 200, seed: int = 0) -> pd.DataFrame:
    """Synthetic CIC-IDS2017-shaped frame: 32 flow features + raw label.

    Attacks skew toward high packet rates and SYN counts so models have
    signal, mirroring make_dataset for the NSL-KDD schema.
    """
    from nids.flowschema import FLOW_FEATURES

    rng = np.random.RandomState(seed)
    is_attack = rng.rand(n) < 0.5

    df = pd.DataFrame(index=range(n))
    for col in FLOW_FEATURES:
        base = rng.rand(n)
        if col in ("flow_pkts_per_s", "syn_flag_cnt", "tot_fwd_pkts"):
            base = base + is_attack * 2.0
        df[col] = base
    df["label"] = np.where(
        is_attack, rng.choice(["DoS Hulk", "PortScan", "SSH-Patator"], n), "BENIGN"
    )
    return df[FLOW_FEATURES + ["label"]]


@pytest.fixture
def synth_df() -> pd.DataFrame:
    return make_dataset()


@pytest.fixture
def synth_split() -> tuple[pd.DataFrame, pd.DataFrame]:
    """(train, test) pair from different seeds."""
    return make_dataset(300, seed=1), make_dataset(100, seed=2)
