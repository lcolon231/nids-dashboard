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

import hmac
import json
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Literal

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from nids import data
from nids.alerts import AlertConfig, AlertNotifier
from nids.anomaly import BASELINE_PATH, WindowAnomalyModel
from nids.association import RULES_PATH
from nids.cic import FlowTransformer
from nids.evaluation import metrics as compute_metrics
from nids.flowschema import CIC_CATEGORIES, FLOW_FEATURES
from nids.models import CIC_METRICS_PATH, DATASETS, MODEL_NAMES, PHASES, model_path
from nids.preprocessing import (
    PROCESSED_DIR,
    FeatureTransformer,
    MULTICLASS_LABELS,
    binary_labels,
    multiclass_labels,
)
from nids.windows import WindowAggregator

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

# --- Phase 11: per-source windowed anomaly detection -------------------------
WINDOW_SECONDS = 60.0
WINDOW_AGGREGATOR = WindowAggregator(window_seconds=WINDOW_SECONDS)
# Rolling buffer of recently scored windows for the dashboard Anomalies panel.
ANOMALY_FEED_MAX = 200
ANOMALY_FEED: deque[dict] = deque(maxlen=ANOMALY_FEED_MAX)
WINDOW_BASELINE_PATH = BASELINE_PATH

# --- Phase 12: outbound attack alerts (configured via env; no-op if unset) ---
NOTIFIER = AlertNotifier(AlertConfig.from_env())


# JSONL logs rotate in place: when a file grows past MAX_LOG_BYTES it is
# trimmed to its last KEEP_LINES entries, bounding disk use (a flood of
# attacks/windows can't fill the disk) and per-request read cost.
MAX_LOG_BYTES = 5_000_000
KEEP_LINES = 10_000


def _append_jsonl(path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > MAX_LOG_BYTES:
        with path.open(encoding="utf-8") as f:
            tail = deque(f, maxlen=KEEP_LINES)
        path.write_text("".join(tail), encoding="utf-8")
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def _append_attack_log(event: dict) -> None:
    _append_jsonl(ATTACK_LOG_PATH, event)


def _append_baseline(window: dict) -> None:
    _append_jsonl(WINDOW_BASELINE_PATH, window)


def _process_finalized_windows(now: float) -> None:
    """Harvest closed windows: always append to the baseline, and if the
    anomaly model is loaded, score them into the anomaly feed."""
    model = STATE.get("anomaly_model")
    for window in WINDOW_AGGREGATOR.pop_finalized(now):
        _append_baseline(window)
        if model is not None:
            scored = {**window, **model.score(window)}
            ANOMALY_FEED.append(scored)
            if scored["is_anomaly"]:
                NOTIFIER.record_anomaly(
                    scored["src_ip"], scored["anomaly_score"], scored["distinct_dst_ports"]
                )


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
    try:
        STATE["anomaly_model"] = WindowAnomalyModel.load()
    except FileNotFoundError:
        STATE["anomaly_model"] = None


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

# Optional API-key auth. When NIDS_API_KEY is set, every request except the
# exempt paths (and CORS preflight) must carry a matching X-API-Key header.
# Unset -> open (backwards compatible; the sensor keeps working until you opt
# in on both sides). Module-level so tests can monkeypatch it.
API_KEY = os.environ.get("NIDS_API_KEY") or None
AUTH_EXEMPT = {"/health", "/docs", "/redoc", "/openapi.json"}


@app.middleware("http")
async def api_key_auth(request: Request, call_next):
    if API_KEY and request.method != "OPTIONS" and request.url.path not in AUTH_EXEMPT:
        provided = request.headers.get("x-api-key", "")
        if not hmac.compare_digest(provided, API_KEY):
            return JSONResponse(
                {"detail": "invalid or missing X-API-Key"}, status_code=401
            )
    return await call_next(request)

ModelName = Literal["nb", "dt", "rf", "xgb"]
PhaseName = Literal["binary", "multiclass"]
DatasetName = Literal["nsl", "cic"]


# Cap batch size so one unauthenticated POST can't exhaust memory (the sensor
# posts tiny batches; this is generous headroom).
MAX_RECORDS = 5000


class PredictRequest(BaseModel):
    """A batch of raw records (41 NSL-KDD or 32 CIC flow features, no label)."""

    records: list[dict[str, Any]] = Field(min_length=1, max_length=MAX_RECORDS)


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
    required = list(REQUIRED_FEATURES[dataset])
    present = set().union(*(r.keys() for r in records)) if records else set()
    missing = set(required) - present
    if missing:
        raise HTTPException(
            status_code=422, detail=f"records missing features: {sorted(missing)}"
        )
    # Restrict to the known feature columns so junk/extra keys (e.g. thousands
    # of attacker-supplied keys) can't blow up the frame with columns.
    return pd.DataFrame(records, columns=required)


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
    logged_at = datetime.now(timezone.utc).isoformat()
    attack_sources: set[str] = set()
    for rec, res in zip(body.records, results):
        # File-activity counts exist only in the NSL-KDD schema; CIC records
        # leave them None and has_file_activity False.
        event = {
            "ts": now,
            "dataset": dataset,
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
        meta = rec.get("meta")
        if res["is_attack"]:
            _append_attack_log({**event, "logged_at": logged_at})
            if meta and meta.get("src_ip"):
                attack_sources.add(meta["src_ip"])
        # Phase 11: feed the flow into per-source windowing (needs sensor meta).
        if meta:
            WINDOW_AGGREGATOR.add(meta, now)
    _process_finalized_windows(now)
    # Phase 12: aggregate + throttle outbound attack alerts.
    attacks = sum(r["is_attack"] for r in results)
    NOTIFIER.record_attacks(attacks, attack_sources)
    NOTIFIER.maybe_flush(now)
    return {
        "count": len(results),
        "attacks": attacks,
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
        # Read only the tail into memory (bounded regardless of file size).
        read_lines = limit * 5 if files_only else limit
        with ATTACK_LOG_PATH.open(encoding="utf-8") as f:
            tail = deque(f, maxlen=read_lines)
        attacks = [json.loads(line) for line in tail if line.strip()]
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


@app.get("/anomalies/recent")
def anomalies_recent(
    limit: int = Query(50, ge=1, le=ANOMALY_FEED_MAX),
    anomalies_only: bool = Query(False),
) -> dict:
    """Recently scored per-source windows, newest first (Anomalies panel).

    Requires a trained window-anomaly model; until then this is empty even as
    the baseline accumulates (see /anomalies/status)."""
    windows = list(ANOMALY_FEED)
    if anomalies_only:
        windows = [w for w in windows if w.get("is_anomaly")]
    windows = windows[-limit:][::-1]
    return {
        "count": len(windows),
        "anomalies": sum(w.get("is_anomaly", False) for w in windows),
        "windows": windows,
    }


@app.get("/anomalies/status")
def anomalies_status() -> dict:
    """Whether the anomaly model is loaded + how much baseline is captured."""
    baseline_windows = 0
    if WINDOW_BASELINE_PATH.exists():
        with WINDOW_BASELINE_PATH.open(encoding="utf-8") as f:
            baseline_windows = sum(1 for line in f if line.strip())
    return {
        "model_loaded": STATE.get("anomaly_model") is not None,
        "window_seconds": WINDOW_SECONDS,
        "baseline_windows_captured": baseline_windows,
        "windows_open": len(WINDOW_AGGREGATOR),
    }


@app.get("/alerts/status")
def alerts_status() -> dict:
    """Alert-notifier config + counters (does not expose the webhook URL)."""
    return NOTIFIER.status()


@app.post("/alerts/test")
def alerts_test() -> dict:
    """Send a test alert immediately (bypasses throttle) to verify delivery."""
    if not NOTIFIER.config.enabled:
        raise HTTPException(
            status_code=503,
            detail="alerts not configured — set NIDS_ALERT_WEBHOOK (or email vars)",
        )
    sent = NOTIFIER.maybe_flush(time.time(), force=True)
    return {"sent": sent, "kind": NOTIFIER.config.kind, "failures": NOTIFIER.failures}
