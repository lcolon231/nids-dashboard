# NIDS Dashboard

A two-tier **Network Intrusion Detection System** dashboard: a Python/FastAPI machine-learning backend trained on the NSL-KDD dataset, and a Next.js 15 frontend that visualizes model performance, dataset composition, discovered attack patterns, and a real-time scored traffic feed.

```
┌─────────────┐   POST /score/live   ┌──────────────────┐   GET /metrics /rules ...   ┌──────────────┐
│   Sensor     │ ───────────────────► │  FastAPI backend  │ ◄────────────────────────── │   Next.js     │
│ (Pi / sim)   │                      │  :8000            │                             │  dashboard    │
└─────────────┘                      │  NB · DT · KMeans │                             │  :3000        │
                                     │  Apriori rules    │                             └──────────────┘
                                     └──────────────────┘
```

## Features

- **Binary + multiclass classification** — Gaussian Naive Bayes and Decision Tree, trained on `KDDTrain+` (125,973 connections), evaluated on `KDDTest+` (22,544 connections, including attack types unseen in training)
- **Unsupervised clustering** — KMeans sweep k=2..10 with inertia + silhouette scoring
- **Association rule mining** — Apriori (mlxtend) surfaces human-readable attack signatures, e.g. `{flag=RSTR, service=private} → probe` (confidence 1.0, lift 10.8)
- **Live scoring** — a sensor client streams connection records to `/score/live`; the dashboard's Live Feed panel shows attacks flagged in near-real time
- **Fully reproducible** — data and model artifacts are gitignored and regenerate from two CLI commands

## Results (KDDTest+)

| Model | Phase | Accuracy | F1 |
|-------|-------|----------|-----|
| Decision Tree | binary | **0.814** | 0.811 |
| Decision Tree | multiclass | 0.763 | 0.574 (macro) |
| Gaussian NB | binary | 0.566 | 0.390 |
| Gaussian NB | multiclass | 0.473 | 0.330 (macro) |

KDDTest+ deliberately contains novel attack types, so ~81% is in line with published single-model baselines — the NB/DT gap is part of what the dashboard illustrates.

## Quickstart

**Prereqs:** Python 3.11, Node 18+

### 1. Backend (API on :8000)

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate            # (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt

python -m nids.data download      # fetch + verify NSL-KDD -> data/raw/
python -m nids.models train       # transformer + NB/DT/KMeans -> data/processed/
python -m nids.association build  # Apriori rules -> data/processed/rules.csv

pytest                            # 41 tests, synthetic fixtures only
uvicorn main:app --reload --port 8000
```

### 2. Frontend (dashboard on :3000)

```powershell
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000**.

### 3. Live feed (optional)

```powershell
cd backend
.venv\Scripts\python sensor_sim.py    # streams 5 records every 2s to /score/live
```

The simulator samples real `KDDTest+` records. A real sensor (e.g., a Raspberry Pi capturing traffic) replaces it by POSTing the same 41-feature JSON to the same endpoint.

## API

| Method | Path | Params | Description |
|--------|------|--------|-------------|
| GET | `/health` | — | status + loaded models |
| POST | `/predict` | `model=nb\|dt`, `phase=binary\|multiclass` | classify a batch of records |
| GET | `/metrics` | `phase=binary\|multiclass` | NB + DT metrics on KDDTest+ (cached) |
| GET | `/dataset/summary` | `split=train\|test` | rows, cols, class distribution |
| GET | `/rules` | — | top 20 association rules by lift |
| POST | `/score/live` | — | batch scoring for the live sensor (DT binary) |
| GET | `/live/recent` | `limit` | rolling buffer of live-scored events |

Interactive docs: **http://localhost:8000/docs**

## Project structure

```
backend/
  nids/
    data.py            NSL-KDD download + verification + loading
    preprocessing.py   FeatureTransformer (one-hot + scaling) + label maps
    models.py          NB/DT training, KMeans sweep, artifact persistence
    association.py     Apriori rule mining -> rules.csv
    evaluation.py      accuracy / precision / recall / F1
  tests/               pytest suite — synthetic fixtures, never the real dataset
  main.py              FastAPI app
  sensor_sim.py        simulated Pi sensor
  SPEC.md              full build spec
frontend/
  app/                 Next.js 15 (App Router)
  components/          MetricsPanel · DatasetPanel · RulesPanel · LiveFeedPanel
  lib/api.ts           typed API client
```

## Stack

**Backend:** FastAPI · scikit-learn · mlxtend · pandas · joblib · pytest
**Frontend:** Next.js 15 · React 19 · TypeScript · Tailwind CSS 4

## Dataset

[NSL-KDD](https://github.com/defcom17/NSL_KDD) — a curated revision of the KDD Cup '99 intrusion detection benchmark. 41 features per connection record; labels cover normal traffic plus attacks in 4 families (DoS, Probe, R2L, U2R).
