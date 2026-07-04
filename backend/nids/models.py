"""Model training + persistence.

Phase 4 (NSL-KDD):
  - NB/DT/RF/XGB, binary AND multiclass
    -> data/processed/{model}_{binary,multiclass}.joblib
  - KMeans sweep k=2..10 (inertia + silhouette on 10k sample),
    pick best k by silhouette -> kmeans.joblib + kmeans_sweep.json
  Trained on KDDTrain+, evaluated on KDDTest+.

Phase 10 (CIC-IDS2017): same model zoo on the 32 modern flow features
  -> cic_{model}_{binary,multiclass}.joblib + cic_transformer.joblib
     + cic_metrics.json (held-out metrics, served by /metrics?dataset=cic).
  Trained/evaluated on a stratified 70/30 split (no canonical split exists).

CLI: python -m nids.models train [--dataset nsl|cic|all]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.cluster import KMeans
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import silhouette_score
from sklearn.naive_bayes import GaussianNB
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from nids import cic, data
from nids.evaluation import metrics
from nids.preprocessing import (
    PROCESSED_DIR,
    FeatureTransformer,
    binary_labels,
    multiclass_labels,
)

RANDOM_STATE = 42
KMEANS_K_RANGE = range(2, 11)
KMEANS_SAMPLE = 10_000

KMEANS_PATH = PROCESSED_DIR / "kmeans.joblib"
KMEANS_SWEEP_PATH = PROCESSED_DIR / "kmeans_sweep.json"
CIC_METRICS_PATH = PROCESSED_DIR / "cic_metrics.json"

MODEL_NAMES = ("nb", "dt", "rf", "xgb")
PHASES = ("binary", "multiclass")
DATASETS = ("nsl", "cic")

# dataset -> {phase: raw-labels -> int array}
LABEL_FNS = {
    "nsl": {"binary": binary_labels, "multiclass": multiclass_labels},
    "cic": {"binary": cic.binary_labels, "multiclass": cic.multiclass_labels},
}


def model_path(model: str, phase: str, dataset: str = "nsl") -> Path:
    """data/processed/[cic_]<model>_<phase>.joblib, validating all names."""
    if model not in MODEL_NAMES:
        raise ValueError(f"unknown model {model!r}; expected one of {MODEL_NAMES}")
    if phase not in PHASES:
        raise ValueError(f"unknown phase {phase!r}; expected one of {PHASES}")
    if dataset not in DATASETS:
        raise ValueError(f"unknown dataset {dataset!r}; expected one of {DATASETS}")
    prefix = "cic_" if dataset == "cic" else ""
    return PROCESSED_DIR / f"{prefix}{model}_{phase}.joblib"


def _make(model: str):
    if model == "nb":
        return GaussianNB()
    if model == "dt":
        return DecisionTreeClassifier(random_state=RANDOM_STATE)
    if model == "rf":
        return RandomForestClassifier(
            n_estimators=100, n_jobs=-1, random_state=RANDOM_STATE
        )
    return XGBClassifier(
        n_estimators=200,
        max_depth=8,
        tree_method="hist",
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )


def train_classifiers(X_train, train_labels, X_test, test_labels, dataset: str = "nsl") -> dict:
    """Train all models x binary/multiclass, persist each, return test metrics."""
    fns = LABEL_FNS[dataset]
    y = {
        phase: (fns[phase](train_labels), fns[phase](test_labels)) for phase in PHASES
    }
    results: dict = {}
    for phase in PHASES:
        y_train, y_test = y[phase]
        for model in MODEL_NAMES:
            clf = _make(model).fit(X_train, y_train)
            path = model_path(model, phase, dataset)
            joblib.dump(clf, path)
            m = metrics(y_test, clf.predict(X_test), phase)
            results.setdefault(phase, {})[model] = m
            print(
                f"[ok  ] {path.stem}: acc={m['accuracy']:.4f} "
                f"f1={m['f1']:.4f} -> {path.name}"
            )
    return results


def kmeans_sweep(X_train) -> dict:
    """Sweep k=2..10 on a 10k sample; pick best k by silhouette.

    Persists the winning model (refit on the full training set) to
    kmeans.joblib and the sweep results to kmeans_sweep.json.
    """
    rng = np.random.RandomState(RANDOM_STATE)
    idx = rng.choice(X_train.shape[0], size=KMEANS_SAMPLE, replace=False)
    sample = X_train[idx]

    sweep = []
    for k in KMEANS_K_RANGE:
        km = KMeans(n_clusters=k, n_init=10, random_state=RANDOM_STATE).fit(sample)
        sil = float(silhouette_score(sample, km.labels_))
        sweep.append({"k": k, "inertia": float(km.inertia_), "silhouette": sil})
        print(f"[ok  ] kmeans k={k}: inertia={km.inertia_:.1f} silhouette={sil:.4f}")

    best_k = max(sweep, key=lambda r: r["silhouette"])["k"]
    print(f"[ok  ] best k by silhouette: {best_k} — refitting on full train set")
    best = KMeans(n_clusters=best_k, n_init=10, random_state=RANDOM_STATE).fit(X_train)
    joblib.dump(best, KMEANS_PATH)

    result = {"best_k": best_k, "sample_size": KMEANS_SAMPLE, "sweep": sweep}
    KMEANS_SWEEP_PATH.write_text(json.dumps(result, indent=2))
    print(f"[ok  ] saved {KMEANS_PATH.name} + {KMEANS_SWEEP_PATH.name}")
    return result


def train() -> None:
    """Full Phase 4 pipeline: transformer + 4 classifiers + KMeans sweep."""
    train_df = data.load("train")
    test_df = data.load("test")

    transformer = FeatureTransformer().fit(train_df)
    transformer.save()
    X_train = transformer.transform(train_df)
    X_test = transformer.transform(test_df)

    train_classifiers(X_train, train_df["label"], X_test, test_df["label"])
    kmeans_sweep(X_train)


def train_cic() -> None:
    """Phase 10: scaler + 4 classifiers on CIC-IDS2017 modern flow features."""
    train_df, test_df = cic.split(cic.load())
    print(f"[ok  ] split: {len(train_df)} train / {len(test_df)} test (stratified)")

    transformer = cic.FlowTransformer().fit(train_df)
    transformer.save()
    X_train = transformer.transform(train_df)
    X_test = transformer.transform(test_df)

    results = train_classifiers(
        X_train, train_df["label"], X_test, test_df["label"], dataset="cic"
    )
    CIC_METRICS_PATH.write_text(json.dumps(results, indent=2))
    print(f"[ok  ] saved held-out metrics -> {CIC_METRICS_PATH.name}")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "train"
    if cmd == "train":
        dataset = argv[argv.index("--dataset") + 1] if "--dataset" in argv else "nsl"
        if dataset not in (*DATASETS, "all"):
            print(f"unknown dataset {dataset!r}; expected nsl, cic, or all")
            return 2
        if dataset in ("nsl", "all"):
            train()
        if dataset in ("cic", "all"):
            train_cic()
        return 0
    print(f"unknown command {cmd!r}; usage: python -m nids.models train [--dataset nsl|cic|all]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
