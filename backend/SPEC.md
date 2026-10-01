# NIDS Dashboard — Backend Spec

Two-tier Network Intrusion Detection System dashboard.
Tier 1: Python FastAPI ML backend (NSL-KDD + CIC-IDS2017 model families, anomaly layer, alerts).
Tier 2: Next.js 15 frontend (separate `frontend/`).
Live input comes from the Raspberry Pi capture sensor (`sensor/`) or the simulator (`sensor_sim.py`).

## Stack
- FastAPI + uvicorn (API, port 8000)
- scikit-learn (GaussianNB, DecisionTree, RandomForest, KMeans, IsolationForest) + XGBoost
- mlxtend (Apriori association rules)
- pandas / numpy / joblib
- pytest + httpx (tests)
- Python 3.11

## Layout
```
backend/
  nids/
    data.py            download + verify NSL-KDD
    preprocessing.py   FeatureTransformer (fit + persist) + label maps
    flowschema.py      modern 32-feature flow schema + CIC label maps
    cic.py             CIC-IDS2017 download + cleaning + split + scaler
    models.py          train NB/DT/RF/XGB (nsl + cic), KMeans sweep
    association.py     Apriori association rules
    windows.py         per-source-IP time-window aggregation
    anomaly.py         IsolationForest window model + baseline capture/train
    alerts.py          throttled outbound alerts (ntfy/Discord/Slack/generic/email)
    evaluation.py      accuracy, precision, recall, F1
  tests/               pytest, synthetic fixtures only
  data/                (gitignored)
    raw/               KDDTrain+.txt, KDDTest+.txt, CIC-IDS2017 CSVs
    processed/         *.joblib, cic_metrics.json, kmeans_sweep.json, rules.csv,
                       attack_log.jsonl, window_baseline.jsonl
  main.py              FastAPI app
  sensor_sim.py        simulated Pi sensor -> POST /score/live
  requirements.txt
```

## Datasets
### NSL-KDD
- Train: `KDDTrain+.txt` — 125,973 rows × 43 cols
- Test:  `KDDTest+.txt`  — 22,544 rows × 43 cols
- No header row. Columns = 41 KDD Cup 99 features + label (col 42) + difficulty (col 43).
- Drop the difficulty column. Source: https://github.com/defcom17/NSL_KDD

### CIC-IDS2017
- 32 flow-metadata features (packet sizes, inter-arrival times, TCP flag counts) — see `flowschema.py`.
- Chosen because they're computable live from packet headers, so they work on encrypted traffic.
- Held-out metrics are computed at training time and persisted to `cic_metrics.json`.

## Regeneration pipeline
Data + model artifacts are gitignored; regenerate locally:
```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python -m nids.data download                # -> data/raw/*.txt (verified)
python -m nids.models train                 # -> NSL transformer + nb/dt/rf/xgb + kmeans
python -m nids.association build            # -> data/processed/rules.csv
python -m nids.cic download                 # optional, ~230 MB
python -m nids.models train --dataset cic   # -> cic_* artifacts + cic_metrics.json
pytest                                      # all green
uvicorn main:app --reload --port 8000
```
Anomaly model: run backend + sensor on normal traffic to fill `window_baseline.jsonl`,
then `python -m nids.anomaly train` and restart uvicorn.

## API endpoints
| Method | Path               | Params                                                       | Notes |
|--------|--------------------|--------------------------------------------------------------|-------|
| GET    | /health            | —                                                            | `{status, models_loaded, transformer_loaded, cic_transformer_loaded}`; exempt from auth |
| POST   | /predict           | model=nb\|dt\|rf\|xgb, phase=binary\|multiclass, dataset=nsl\|cic | 503 if model unloaded |
| GET    | /metrics           | phase=binary\|multiclass, dataset=nsl\|cic                   | all four models; nsl computed on KDDTest+ and cached, cic read from `cic_metrics.json` |
| GET    | /dataset/summary   | split=train\|test                                            | rows, cols, class distribution |
| GET    | /rules             | —                                                            | top 20 by lift; 503 if rules.csv missing |
| POST   | /score/live        | dataset=nsl\|cic                                             | DT binary scoring for the sensor; feeds live buffer, attack log, anomaly windows, alerts |
| GET    | /live/recent       | limit (default 50)                                           | rolling buffer of live-scored events |
| GET    | /attacks/log       | limit (≤1000), files_only                                    | persisted JSONL attack log, newest-first |
| GET    | /anomalies/recent  | limit, anomalies_only                                        | recently scored per-source windows, newest-first |
| GET    | /anomalies/status  | —                                                            | model loaded? baseline windows captured, windows open |
| GET    | /alerts/status     | —                                                            | alert channel + throttle config (no secrets) |
| POST   | /alerts/test       | —                                                            | send a test alert now (bypasses throttle) |

CORS enabled for all origins (Next.js dashboard).

## Security
- Optional API key: when `NIDS_API_KEY` is set, every request except `/health` (and CORS preflight)
  needs a matching `X-API-Key` header. The sensor takes `--api-key`; the frontend reads
  `NEXT_PUBLIC_NIDS_API_KEY` at build time.
- Request batches capped at `MAX_RECORDS` (5000) and restricted to known feature columns.
- `attack_log.jsonl` / `window_baseline.jsonl` rotate in place at `MAX_LOG_BYTES` (5 MB) and are tail-read.
- CIC archive extraction rejects zip-slip paths.

## Build phases
1. Backend scaffold ✅
2. Dataset download + verify ✅
3. Preprocessing (FeatureTransformer) ✅
4. Models (NB, DT, KMeans sweep; later RF + XGBoost) ✅
5. Association rules (Apriori) ✅
6. FastAPI endpoints ✅
7. Tests (synthetic fixtures) ✅
8. Next.js frontend ✅
9. Live sensor integration (/score/live, sensor_sim.py, Raspberry Pi capture sensor, Live Feed panel) ✅
10. CIC-IDS2017 modern-traffic model family (`dataset=cic`) ✅
11. Per-source windowed anomaly detection (IsolationForest, Anomalies panel) ✅
12. Outbound attack alerts (ntfy/Discord/Slack/generic/email) ✅
13. Hardening (API-key auth, input caps, log rotation, safe zip extract) + deployment guide (`docs/DEPLOY.md`) ✅
14. CI (GitHub Actions: backend + sensor pytest, frontend lint/typecheck/build) ✅

## Running the full stack
```
cd backend  && uvicorn main:app --reload --port 8000
cd backend  && python sensor_sim.py            # optional: feeds the Live Feed panel
cd frontend && npm run dev                     # dashboard on http://localhost:3000
```
For a real sensor and running everything as services, see `sensor/README.md` and `docs/DEPLOY.md`.
