"""FastAPI application for the NIDS dashboard.

Phase 6 implements 5 core endpoints + Phase 9 adds /score/live:
  GET  /health
  POST /predict           (model=nb|dt, phase=binary|multiclass)
  GET  /metrics           (phase=binary|multiclass)
  GET  /dataset/summary   (split=train|test)
  GET  /rules
  POST /score/live        (batch scoring for the Pi sensor)

CORS enabled for all origins (Next.js dev server on :3000).
Run: uvicorn main:app --reload --port 8000
"""
from __future__ import annotations

import json
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Literal

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from nids import data
from nids.association import RULES_PATH
from nids.evaluation import metrics as compute_metrics
from nids.models import MODEL_NAMES, PHASES, model_path
from nids.preprocessing import (
    PROCESSED_DIR,
    FeatureTransformer,
    MULTICLASS_LABELS,
    binary_labels,
    multiclass_labels,
)

BINARY_LABELS = ["normal", "attack"]

# --- app state: artifacts loaded at startup ----------------------------------
STATE: dict[str, Any] = {"transformer": None, "models": {}, "metrics_cache": {}}

# Rolling buffer of recently scored live events for the dashboard Live Feed.
LIVE_FEED_MAX = 200
LIVE_FEED: deque[dict] = deque(maxlen=LIVE_FEED_MAX)

# Host-impact content features carried into live events. NSL-KDD provides
# these as per-connection COUNTS (e.g. files created), not filenames.
FILE_ACTIVITY_FEATURES = (
    "num_file_creations",
    "num_access_files",
    "num_shells",
    "num_root",
    "root_shell",
    "num_compromised",
    "hot",
)

# Persistent attack log (JSONL, one event per line). Survives restarts.
# Module-level so tests can monkeypatch it to a tmp path.
ATTACK_LOG_PATH = PROCESSED_DIR / "attack_log.jsonl"


def _append_attack_log(event: dict) -> None:
    ATTACK_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ATTACK_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def _load_artifacts() -> None:
    """Load transformer + all models that exist; missing ones -> 503 later."""
    try:
        STATE["transformer"] = FeatureTransformer.load()
    except FileNotFoundError:
        STATE["transformer"] = None
    STATE["models"] = {}
    for model in MODEL_NAMES:
        for phase in PHASES:
            path = model_path(model, phase)
            if path.exists():
                STATE["models"][(model, phase)] = joblib.load(path)


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


class PredictRequest(BaseModel):
    """A batch of raw NSL-KDD records (41 features each, no label)."""

    records: list[dict[str, Any]] = Field(min_length=1)


def _get_model(model: str, phase: str):
    clf = STATE["models"].get((model, phase))
    if clf is None or STATE["transformer"] is None:
        raise HTTPException(
            status_code=503,
            detail=f"model {model}_{phase} not loaded — run `python -m nids.models train`",
        )
    return clf


def _records_to_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(records)
    missing = set(data.FEATURE_COLUMNS) - set(df.columns)
    if missing:
        raise HTTPException(
            status_code=422, detail=f"records missing features: {sorted(missing)}"
        )
    return df


def _predict(records: list[dict[str, Any]], model: str, phase: str) -> list[dict]:
    clf = _get_model(model, phase)
    X = STATE["transformer"].transform(_records_to_frame(records))
    preds = clf.predict(X)
    names = BINARY_LABELS if phase == "binary" else MULTICLASS_LABELS
    return [
        {"prediction": int(p), "label": names[int(p)], "is_attack": bool(p != 0)}
        for p in preds
    ]


# --- endpoints ----------------------------------------------------------------
@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "models_loaded": sorted(f"{m}_{p}" for (m, p) in STATE["models"]),
        "transformer_loaded": STATE["transformer"] is not None,
    }


@app.post("/predict")
def predict(
    body: PredictRequest,
    model: ModelName = Query("dt"),
    phase: PhaseName = Query("binary"),
) -> dict:
    results = _predict(body.records, model, phase)
    return {"model": model, "phase": phase, "count": len(results), "results": results}


@app.get("/metrics")
def get_metrics(phase: PhaseName = Query("binary")) -> dict:
    """NB + DT metrics on KDDTest+, computed once per phase and cached."""
    if phase not in STATE["metrics_cache"]:
        if STATE["transformer"] is None:
            raise HTTPException(status_code=503, detail="transformer not loaded")
        try:
            test_df = data.load("test")
        except FileNotFoundError as e:
            raise HTTPException(status_code=503, detail=str(e))
        X = STATE["transformer"].transform(test_df)
        y = (
            binary_labels(test_df["label"])
            if phase == "binary"
            else multiclass_labels(test_df["label"])
        )
        STATE["metrics_cache"][phase] = {
            model: compute_metrics(y, _get_model(model, phase).predict(X), phase)
            for model in MODEL_NAMES
        }
    return {"phase": phase, "split": "test", "metrics": STATE["metrics_cache"][phase]}


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
def score_live(body: PredictRequest) -> dict:
    """Batch scoring for the Pi sensor (Phase 9): DT binary, flag attacks."""
    results = _predict(body.records, "dt", "binary")
    now = time.time()
    logged_at = datetime.now(timezone.utc).isoformat()
    for rec, res in zip(body.records, results):
        event = {
            "ts": now,
            "protocol_type": rec.get("protocol_type"),
            "service": rec.get("service"),
            "flag": rec.get("flag"),
            **{k: rec.get(k) for k in FILE_ACTIVITY_FEATURES},
            "has_file_activity": bool(
                (rec.get("num_file_creations") or 0) > 0
                or (rec.get("num_access_files") or 0) > 0
            ),
            **res,
        }
        LIVE_FEED.append(event)
        if res["is_attack"]:
            _append_attack_log({**event, "logged_at": logged_at})
    return {
        "count": len(results),
        "attacks": sum(r["is_attack"] for r in results),
        "results": results,
    }


@app.get("/attacks/log")
def attacks_log(
    limit: int = Query(100, ge=1, le=1000),
    files_only: bool = Query(False),
) -> dict:
    """Persisted attack log, newest-first. files_only keeps host-impact hits."""
    attacks: list[dict] = []
    if ATTACK_LOG_PATH.exists():
        with ATTACK_LOG_PATH.open(encoding="utf-8") as f:
            attacks = [json.loads(line) for line in f if line.strip()]
    if files_only:
        attacks = [a for a in attacks if a.get("has_file_activity")]
    attacks = attacks[-limit:][::-1]  # file is append-order; newest first
    return {"count": len(attacks), "attacks": attacks}


@app.get("/live/recent")
def live_recent(limit: int = Query(50, ge=1, le=LIVE_FEED_MAX)) -> dict:
    """Most recent live-scored records, newest first (dashboard Live Feed)."""
    events = list(LIVE_FEED)[-limit:][::-1]
    return {
        "count": len(events),
        "attacks": sum(e["is_attack"] for e in events),
        "events": events,
    }
