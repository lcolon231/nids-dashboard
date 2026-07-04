"""FastAPI application for the NIDS dashboard.

Phase 6 implements 5 core endpoints, Phase 9 adds /score/live, Phase 10 adds
a second model family trained on CIC-IDS2017 (dataset=nsl|cic on /predict,
/metrics, /score/live; defaults preserve the original NSL-KDD behavior):
  GET  /health
  POST /predict           (model=nb|dt|rf|xgb, phase=binary|multiclass, dataset=nsl|cic)
  GET  /metrics           (phase=binary|multiclass, dataset=nsl|cic)
  GET  /dataset/summary   (split=train|test)
  GET  /rules
  POST /score/live        (batch scoring for the Pi sensor, dataset=nsl|cic)

CORS enabled for all origins (Next.js dev server on :3000).
Run: uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import json
import time
from collections import deque
from contextlib import asynccontextmanager
from typing import Any, Literal

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from nids import data
from nids.association import RULES_PATH
from nids.cic import FlowTransformer
from nids.evaluation import metrics as compute_metrics
from nids.flowschema import CIC_CATEGORIES, FLOW_FEATURES
from nids.models import CIC_METRICS_PATH, DATASETS, MODEL_NAMES, PHASES, model_path
from nids.preprocessing import (
    FeatureTransformer,
    MULTICLASS_LABELS,
    binary_labels,
    multiclass_labels,
)

BINARY_LABELS = ["normal", "attack"]
REQUIRED_FEATURES = {"nsl": data.FEATURE_COLUMNS, "cic": FLOW_FEATURES}

# --- app state: artifacts loaded at startup ----------------------------------
STATE: dict[str, Any] = {
    "transformers": {},  # dataset -> fitted transformer
    "models": {},  # (dataset, model, phase) -> fitted classifier
    "metrics_cache": {},
}

# Rolling buffer of recently scored live events for the dashboard Live Feed.
LIVE_FEED_MAX = 200
LIVE_FEED: deque[dict] = deque(maxlen=LIVE_FEED_MAX)


def _load_artifacts() -> None:
    """Load transformers + all models that exist; missing ones -> 503 later."""
    STATE["transformers"] = {}
    for dataset, loader in (("nsl", FeatureTransformer.load), ("cic", FlowTransformer.load)):
        try:
            STATE["transformers"][dataset] = loader()
        except FileNotFoundError:
            pass
    STATE["models"] = {}
    for dataset in DATASETS:
        for model in MODEL_NAMES:
            for phase in PHASES:
                path = model_path(model, phase, dataset)
                if path.exists():
                    STATE["models"][(dataset, model, phase)] = joblib.load(path)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_artifacts()
    yield


app = FastAPI(title="NIDS Dashboard API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ModelName = Literal["nb", "dt", "rf", "xgb"]
PhaseName = Literal["binary", "multiclass"]
DatasetName = Literal["nsl", "cic"]


class PredictRequest(BaseModel):
    """A batch of raw records (41 NSL-KDD or 32 CIC flow features, no label)."""

    records: list[dict[str, Any]] = Field(min_length=1)


def _get_model(model: str, phase: str, dataset: str = "nsl"):
    clf = STATE["models"].get((dataset, model, phase))
    if clf is None or dataset not in STATE["transformers"]:
        prefix = "cic_" if dataset == "cic" else ""
        raise HTTPException(
            status_code=503,
            detail=(
                f"model {prefix}{model}_{phase} not loaded — run "
                f"`python -m nids.models train --dataset {dataset}`"
            ),
        )
    return clf


def _records_to_frame(records: list[dict[str, Any]], dataset: str = "nsl") -> pd.DataFrame:
    df = pd.DataFrame(records)
    missing = set(REQUIRED_FEATURES[dataset]) - set(df.columns)
    if missing:
        raise HTTPException(
            status_code=422, detail=f"records missing features: {sorted(missing)}"
        )
    return df


def _predict(
    records: list[dict[str, Any]], model: str, phase: str, dataset: str = "nsl"
) -> list[dict]:
    clf = _get_model(model, phase, dataset)
    X = STATE["transformers"][dataset].transform(_records_to_frame(records, dataset))
    preds = clf.predict(X)
    if phase == "binary":
        names = BINARY_LABELS
    else:
        names = MULTICLASS_LABELS if dataset == "nsl" else CIC_CATEGORIES
    return [
        {"prediction": int(p), "label": names[int(p)], "is_attack": bool(p != 0)}
        for p in preds
    ]


# --- endpoints ----------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "models_loaded": sorted(
            f"{'cic_' if d == 'cic' else ''}{m}_{p}" for (d, m, p) in STATE["models"]
        ),
        "transformer_loaded": "nsl" in STATE["transformers"],
        "cic_transformer_loaded": "cic" in STATE["transformers"],
    }


@app.post("/predict")
def predict(
    body: PredictRequest,
    model: ModelName = Query("dt"),
    phase: PhaseName = Query("binary"),
    dataset: DatasetName = Query("nsl"),
) -> dict:
    results = _predict(body.records, model, phase, dataset)
    return {
        "model": model,
        "phase": phase,
        "dataset": dataset,
        "count": len(results),
        "results": results,
    }


@app.get("/metrics")
def get_metrics(
    phase: PhaseName = Query("binary"), dataset: DatasetName = Query("nsl")
) -> dict:
    """All-model test metrics. nsl: computed on KDDTest+ once and cached.
    cic: read from cic_metrics.json (persisted at training time)."""
    if dataset == "cic":
        if not CIC_METRICS_PATH.exists():
            raise HTTPException(
                status_code=503,
                detail="cic_metrics.json missing — run `python -m nids.models train --dataset cic`",
            )
        results = json.loads(CIC_METRICS_PATH.read_text())
        return {"phase": phase, "split": "test", "dataset": "cic", "metrics": results[phase]}
    if phase not in STATE["metrics_cache"]:
        if "nsl" not in STATE["transformers"]:
            raise HTTPException(status_code=503, detail="transformer not loaded")
        try:
            test_df = data.load("test")
        except FileNotFoundError as e:
            raise HTTPException(status_code=503, detail=str(e))
        X = STATE["transformers"]["nsl"].transform(test_df)
        y = (
            binary_labels(test_df["label"])
            if phase == "binary"
            else multiclass_labels(test_df["label"])
        )
        STATE["metrics_cache"][phase] = {
            model: compute_metrics(y, _get_model(model, phase).predict(X), phase)
            for model in MODEL_NAMES
        }
    return {
        "phase": phase,
        "split": "test",
        "dataset": "nsl",
        "metrics": STATE["metrics_cache"][phase],
    }


@app.get("/dataset/summary")
def dataset_summary(split: Literal["train", "test"] = Query("train")) -> dict:
    try:
        df = data.load(split)
    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    categories = pd.Series(multiclass_labels(df["label"])).map(
        lambda i: MULTICLASS_LABELS[i]
    )
    return {
        "split": split,
        "rows": int(df.shape[0]),
        "cols": int(df.shape[1]),
        "class_distribution": categories.value_counts().to_dict(),
        "label_distribution": df["label"].value_counts().to_dict(),
    }


@app.get("/rules")
def rules() -> dict:
    """Top 20 association rules by lift."""
    if not RULES_PATH.exists():
        raise HTTPException(
            status_code=503,
            detail="rules.csv missing — run `python -m nids.association build`",
        )
    top = pd.read_csv(RULES_PATH).head(20)
    return {"count": len(top), "rules": top.to_dict(orient="records")}


@app.post("/score/live")
def score_live(body: PredictRequest, dataset: DatasetName = Query("nsl")) -> dict:
    """Batch scoring for the Pi sensor (Phase 9): DT binary, flag attacks.

    CIC records carry protocol_type/service/flag as extra display-only keys
    (the model ignores them), so the Live Feed renders both schemas.
    """
    results = _predict(body.records, "dt", "binary", dataset)
    now = time.time()
    for rec, res in zip(body.records, results):
        LIVE_FEED.append(
            {
                "ts": now,
                "dataset": dataset,
                "protocol_type": rec.get("protocol_type"),
                "service": rec.get("service"),
                "flag": rec.get("flag"),
                **res,
            }
        )
    return {
        "count": len(results),
        "attacks": sum(r["is_attack"] for r in results),
        "results": results,
    }


@app.get("/live/recent")
def live_recent(limit: int = Query(50, ge=1, le=LIVE_FEED_MAX)) -> dict:
    """Most recent live-scored records, newest first (dashboard Live Feed)."""
    events = list(LIVE_FEED)[-limit:][::-1]
    return {
        "count": len(events),
        "attacks": sum(e["is_attack"] for e in events),
        "events": events,
    }
