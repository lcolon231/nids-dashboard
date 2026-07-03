# NIDS Dashboard — Backend Spec

Two-tier Network Intrusion Detection System dashboard.
Tier 1: Python FastAPI ML backend on the NSL-KDD dataset.
Tier 2: Next.js 15 frontend (separate `frontend/`).

## Stack
- FastAPI + uvicorn (API, port 8000)
- scikit-learn (GaussianNB, DecisionTree, RandomForest, KMeans) + XGBoost
- mlxtend (Apriori association rules)
- pandas / numpy / joblib
- pytest + httpx (tests)
- Python 3.11

## Layout
```
backend/
  nids/
    data.py            download + verify NSL-KDD
    preprocessing.py   FeatureTransformer (fit + persist)
    models.py          train GaussianNB, DecisionTree, KMeans
    association.py     Apriori association rules
    evaluation.py      accuracy, precision, recall, F1
  tests/               pytest, synthetic fixtures only
  data/
    raw/               KDDTrain+.txt, KDDTest+.txt   (gitignored)
    processed/         *.joblib, kmeans_sweep.json, rules.csv (gitignored)
  main.py              FastAPI app
  sensor_sim.py        simulated Pi sensor -> POST /score/live
  requirements.txt
```

## Dataset — NSL-KDD
- Train: `KDDTrain+.txt` — 125,973 rows × 43 cols
- Test:  `KDDTest+.txt`  — 22,544 rows × 43 cols
- No header row. Columns = 41 KDD Cup 99 features + label (col 42) + difficulty (col 43).
- Drop the difficulty column. Source: https://github.com/defcom17/NSL_KDD

## Regeneration pipeline
Data + model artifacts are gitignored; regenerate locally:
```
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python -m nids.data download      # -> data/raw/*.txt (verified)
python -m nids.models train       # -> transformer + nb/dt/kmeans artifacts
python -m nids.association build   # -> data/processed/rules.csv
pytest                            # all green
uvicorn main:app --reload --port 8000
```

## API endpoints
| Method | Path              | Params                          | Notes |
|--------|-------------------|---------------------------------|-------|
| GET    | /health           | —                               | `{status, models_loaded}` |
| POST   | /predict          | model=nb\|dt\|rf\|xgb, phase=binary\|multiclass | 503 if model unloaded |
| GET    | /metrics          | phase=binary\|multiclass        | NB + DT metrics on KDDTest+ |
| GET    | /dataset/summary  | split=train\|test               | rows, cols, class distribution |
| GET    | /rules            | —                               | top 20 by lift; 503 if rules.csv missing |
| POST   | /score/live       | —                               | batch scoring for Pi sensor (Phase 9) |
| GET    | /live/recent      | limit (default 50)              | rolling buffer of live-scored events for the Live Feed panel |

CORS enabled for all origins (Next.js dev server).

## Build phases
1. Backend scaffold ✅
2. Dataset download + verify ✅
3. Preprocessing (FeatureTransformer) ✅
4. Models (NB, DT, KMeans sweep) ✅
5. Association rules (Apriori) ✅
6. FastAPI endpoints ✅
7. Tests (synthetic fixtures) ✅
8. Next.js frontend (4 panels) ✅
9. Live sensor integration (/score/live + sensor_sim.py + Live Feed panel) ✅

## Running the full stack
```
cd backend  && uvicorn main:app --reload --port 8000
cd backend  && python sensor_sim.py            # optional: feeds the Live Feed panel
cd frontend && npm run dev                     # dashboard on http://localhost:3000
```
