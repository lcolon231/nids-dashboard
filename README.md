# NIDS Dashboard

[![CI](https://github.com/lcolon231/nids-dashboard/actions/workflows/ci.yml/badge.svg)](https://github.com/lcolon231/nids-dashboard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A two-tier **Network Intrusion Detection System** dashboard: a Python/FastAPI machine-learning backend and a Next.js 15 frontend. It trains supervised classifiers on two datasets (NSL-KDD and CIC-IDS2017), mines attack signatures, scores live traffic from a real Raspberry Pi packet-capture sensor, flags scans/floods with an unsupervised anomaly layer trained on your own network, and pushes alerts to your phone when you're attacked.

![NIDS Dashboard — model performance, dataset summary, association rules, live feed, and anomaly panels](docs/screenshot.png)

```
┌──────────────┐  POST /score/live   ┌──────────────────────────────┐   GET /metrics /anomalies …  ┌──────────────┐
│  Pi sensor   │ ───41 NSL / 32 CIC─► │       FastAPI backend         │ ◄────────────────────────── │   Next.js     │
│  (scapy)     │                      │  :8000                        │                             │  dashboard    │
│  or sim      │                      │  NB·DT·RF·XGB  (NSL + CIC)    │ ──────────────────────────► │  :3000        │
└──────────────┘                      │  KMeans · Apriori rules       │                             └──────────────┘
                                      │  per-source anomaly (iForest) │
                                      │  attack alerts ─► 📱 ntfy/…    │
                                      └──────────────────────────────┘
```

**Contents:** [Features](#features) · [Results](#results) · [Quickstart](#quickstart) · [API](#api) · [Anomaly layer](#anomaly-layer-train-on-your-own-traffic) · [Alerts](#attack-alerts-get-notified-when-attacked) · [Security](#security) · [Testing & CI](#testing--ci) · [Project structure](#project-structure) · [Limitations](#limitations)

## Features

- **Binary + multiclass classification** — Gaussian Naive Bayes, Decision Tree, Random Forest, and XGBoost, trained on `KDDTrain+` (125,973 connections), evaluated on `KDDTest+` (22,544 connections, including attack types unseen in training)
- **Modern traffic models (CIC-IDS2017)** — a second model family trained on 32 flow-metadata features (sizes, timings, TCP flags) that work on today's encrypted traffic; toggle `nsl`/`cic` in the dashboard, select with `dataset=cic` on the API, or run the Pi sensor with `--schema cic`
- **Unsupervised clustering** — KMeans sweep k=2..10 with inertia + silhouette scoring
- **Association rule mining** — Apriori (mlxtend) surfaces human-readable attack signatures, e.g. `{flag=RSTR, service=private} → probe` (confidence 1.0, lift 10.8)
- **Live scoring from a real sensor** — a Raspberry Pi sniffs traffic, assembles flows, derives features on the fly, and streams them to `/score/live`; the Live Feed panel shows attacks flagged in near-real time
- **Unsupervised anomaly layer** — per-source-IP time-window aggregation (port/host fan-out, failed-connection ratio, byte volume) fed to an IsolationForest trained on *your own* network's normal traffic. Catches scans and floods the per-flow models miss (a single probe is featureless; one source hitting 999 ports in 5s is not). No labels needed
- **Attack alerts** — phone push (ntfy.sh), Discord/Slack message, or email when you're attacked. Aggregated + throttled so a scan sends one summary alert, not thousands. Configured entirely by environment variables; a no-op until set
- **Persistent attack log** — every flagged attack is appended to a JSONL log enriched with NSL-KDD's file-activity features (`num_file_creations`, `num_access_files`, `root_shell`, …); the Live Feed shows a 📁 host-impact badge on attacks that touched files
- **Hardened API** — optional API-key auth, request-size caps, rotating logs, zip-slip-safe dataset extraction
- **Reproducible** — data and model artifacts are gitignored and regenerate from a handful of CLI commands; tests use synthetic fixtures only and run in CI

## Results

### NSL-KDD (`KDDTest+`)

| Model | Binary acc / F1 | Multiclass acc / F1 (macro) |
|-------|-----------------|------------------------------|
| Decision Tree | **0.814** / 0.811 | 0.763 / 0.574 |
| XGBoost | 0.790 / 0.780 | **0.776** / 0.561 |
| Random Forest | 0.779 / 0.765 | 0.741 / 0.509 |
| Gaussian NB | 0.566 / 0.390 | 0.473 / 0.330 |

KDDTest+ deliberately contains novel attack types, so ~78–81% is in line with published single-model baselines. Notably the single Decision Tree edges out the ensembles on binary detection here — a known NSL-KDD quirk (ensembles fit the training attack distribution more tightly and generalize slightly worse to unseen attack types).

### CIC-IDS2017 (stratified 30% hold-out)

| Model | Binary acc / F1 | Multiclass acc / F1 (macro) |
|-------|-----------------|------------------------------|
| XGBoost | **0.999** / **0.998** | **0.999** / 0.940 |
| Random Forest | **0.999** / 0.997 | **0.999** / **0.949** |
| Decision Tree | **0.999** / 0.996 | 0.998 / 0.928 |
| Gaussian NB | 0.555 / 0.463 | 0.370 / 0.343 |

CIC-IDS2017 has no canonical test split, so these come from a random stratified 70/30 split of the same capture — train and test share attack tools and network, which is why scores are near-perfect. Treat them as an upper bound, not a prediction of performance on your network; that's what the anomaly layer is for.

## Quickstart

**Prereqs:** Python 3.11, Node 18.18+

### 1. Backend (API on :8000)

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate            # (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt

python -m nids.data download      # fetch + verify NSL-KDD -> data/raw/
python -m nids.models train       # transformer + NB/DT/RF/XGB + KMeans -> data/processed/
python -m nids.association build  # Apriori rules -> data/processed/rules.csv

# optional: modern-traffic models (CIC-IDS2017, ~230 MB download)
python -m nids.cic download
python -m nids.models train --dataset cic

uvicorn main:app --reload --port 8000
```

Interactive API docs: **http://localhost:8000/docs**

### 2. Frontend (dashboard on :3000)

```powershell
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000**. Set `NEXT_PUBLIC_API_URL` if the backend isn't on `127.0.0.1:8000` (see [frontend/README.md](frontend/README.md)).

### 3. Live feed — simulator (optional)

```powershell
cd backend
.venv\Scripts\python sensor_sim.py    # streams 5 real KDDTest+ records every 2s to /score/live
```

### 4. Live feed — real Pi sensor (optional)

A real packet-capture sensor lives in [`sensor/`](sensor/README.md). It sniffs live traffic (scapy), assembles flows, derives NSL-KDD (41) or CIC (32) features on the fly, and POSTs to the same `/score/live` endpoint:

```bash
cd sensor
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo .venv/bin/python -m nids_sensor --iface eth0 --url http://<backend-host>:8000 --schema cic
```

See [sensor/README.md](sensor/README.md) for capture permissions, feature-derivation notes, and limitations, and [docs/DEPLOY.md](docs/DEPLOY.md) to run the backend, frontend, and sensor as services.

## API

| Method | Path | Params | Description |
|--------|------|--------|-------------|
| GET | `/health` | — | status + loaded models (never requires auth) |
| POST | `/predict` | `model=nb\|dt\|rf\|xgb`, `phase=binary\|multiclass`, `dataset=nsl\|cic` | classify a batch of records |
| GET | `/metrics` | `phase=binary\|multiclass`, `dataset=nsl\|cic` | all-model held-out metrics |
| GET | `/dataset/summary` | `split=train\|test` | rows, cols, class distribution |
| GET | `/rules` | — | top 20 association rules by lift |
| POST | `/score/live` | `dataset=nsl\|cic` | batch scoring for the live sensor (DT binary) |
| GET | `/live/recent` | `limit` | rolling buffer of live-scored events |
| GET | `/attacks/log` | `limit` (≤1000), `files_only` | persisted attack log (JSONL), newest-first |
| GET | `/anomalies/recent` | `limit`, `anomalies_only` | recently scored per-source windows, newest-first |
| GET | `/anomalies/status` | — | anomaly-model loaded? + baseline windows captured |
| GET | `/alerts/status` | — | alert channel + throttle config (no secrets) |
| POST | `/alerts/test` | — | send a test alert now (bypasses throttle) |

`dataset=nsl` (default) uses the NSL-KDD 41-feature models; `dataset=cic` uses the CIC-IDS2017 32-feature flow-metadata models.

## Anomaly layer (train on your own traffic)

The supervised models score each flow in isolation, so they miss scans and floods — a lone probe is nearly featureless. The anomaly layer groups flows by source IP over 60-second windows and learns your network's normal fan-out/failure profile:

```powershell
# 1. Run the backend + sensor normally for a while (NO attacks) — every closed
#    window is appended to data/processed/window_baseline.jsonl automatically.
# 2. Train the IsolationForest on that baseline:
python -m nids.anomaly train
# 3. Restart uvicorn; /anomalies/status now shows model_loaded: true and the
#    dashboard's Anomalies panel scores live windows. Then stage a scan
#    (nmap against the sensor host) and watch it flag.
```

Windows need source IPs, so this layer is fed by the real sensor, not the simulator.

## Attack alerts (get notified when attacked)

Set environment variables on the backend host before starting uvicorn. Alerts are a no-op until configured, aggregated + throttled so a scan sends one summary (not thousands), and per-flow attacks must cross `MIN_ATTACKS` to fire (anomalous windows always fire).

```powershell
# Phone push via ntfy.sh — install the ntfy app, subscribe to a topic, then:
$env:NIDS_ALERT_KIND    = "ntfy"
$env:NIDS_ALERT_WEBHOOK = "https://ntfy.sh/your-secret-topic-name"
uvicorn main:app --host 0.0.0.0 --port 8000
# verify delivery lands on your phone:
curl -X POST http://127.0.0.1:8000/alerts/test
```

| Variable | Default | Purpose |
|----------|---------|---------|
| `NIDS_ALERT_KIND` | `ntfy` | `ntfy` \| `discord` \| `slack` \| `generic` \| `email` |
| `NIDS_ALERT_WEBHOOK` | — | URL to POST to (ntfy topic / Discord / Slack / custom) |
| `NIDS_ALERT_COOLDOWN` | `60` | min seconds between alerts |
| `NIDS_ALERT_MIN_ATTACKS` | `5` | per-flow attacks needed to alert |
| `NIDS_ALERT_EMAIL_TO` / `_SMTP_HOST` / `_SMTP_PORT` / `_SMTP_USER` / `_SMTP_PASSWORD` | — | email channel (use a Gmail App Password) |

Discord/Slack use that channel's incoming-webhook URL; `generic` POSTs `{"title","message"}` JSON to any endpoint.

## Security

The API is unauthenticated by default (fine on an isolated home lab). For anything beyond that, set an API key — the backend then requires an `X-API-Key` header on every request except `/health`:

```powershell
$env:NIDS_API_KEY = "a-long-random-string"
uvicorn main:app --host 0.0.0.0 --port 8000
```

Point the sensor at the same key (or set `NIDS_API_KEY` in its environment):

```bash
sudo sensor/.venv/bin/python -m nids_sensor --iface wlan0 --url http://<host>:8000 \
     --schema cic --api-key "a-long-random-string"
```

The dashboard needs the key too — set it before building the frontend:

```powershell
$env:NEXT_PUBLIC_NIDS_API_KEY = "a-long-random-string"
npm run build
```

`NEXT_PUBLIC_*` values are compiled into the browser bundle, so anyone who can load the dashboard can read the key. Fine on a trusted LAN; don't expose the dashboard publicly with this setup.

Authenticating the sensor feed also closes the **anomaly-baseline poisoning** vector — without it, anyone on the network can inject windows into your training baseline via `/score/live`. Other hardening baked in: request batches are capped (`MAX_RECORDS`) and restricted to known feature columns (memory-exhaustion DoS), the attack/baseline JSONL logs rotate in place at a byte cap (disk DoS) and are tail-read (`/attacks/log` stays bounded regardless of log size), and CIC archive extraction rejects zip-slip paths.

## Testing & CI

```powershell
cd backend && pytest        # 123 tests — synthetic fixtures, never the real dataset
cd sensor  && pytest        # 48 tests — pure-Python, no capture or root needed
cd frontend && npm run lint && npx tsc --noEmit && npm run build
```

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs all three on every pull request and push to `master`.

## Project structure

```
backend/
  nids/
    data.py            NSL-KDD download + verification + loading
    preprocessing.py   FeatureTransformer (one-hot + scaling) + label maps
    flowschema.py      modern 32-feature flow schema + CIC label maps
    cic.py             CIC-IDS2017 download + cleaning + split + scaler
    windows.py         per-source-IP time-window aggregation
    anomaly.py         IsolationForest window-anomaly model + baseline/train
    alerts.py          throttled attack alerts (ntfy/Discord/Slack/email)
    models.py          model training (NSL-KDD + CIC), KMeans sweep, persistence
    association.py     Apriori rule mining -> rules.csv
    evaluation.py      accuracy / precision / recall / F1
  tests/               pytest suite — synthetic fixtures only
  main.py              FastAPI app
  sensor_sim.py        simulated Pi sensor
  SPEC.md              full build spec
frontend/
  app/                 Next.js 15 (App Router)
  components/          Metrics · Dataset · Rules · LiveFeed · Anomaly panels
  lib/api.ts           typed API client
sensor/
  nids_sensor/         Raspberry Pi capture client (scapy -> flows -> features)
  tests/               pytest suite — pure-Python, no capture required
deploy/                Pi sensor systemd unit + env template
docs/                  DEPLOY.md (run everything as services) + screenshot
.github/workflows/     CI
```

## Stack

**Backend:** FastAPI · scikit-learn (incl. IsolationForest) · XGBoost · mlxtend · pandas · joblib · pytest
**Sensor:** scapy · httpx (pure-Python core, testable without capture or root)
**Frontend:** Next.js 15 · React 19 · TypeScript · Tailwind CSS 4
**CI:** GitHub Actions

## Datasets

- [NSL-KDD](https://github.com/defcom17/NSL_KDD) — a curated revision of the KDD Cup '99 benchmark. 41 features per connection; labels cover normal traffic plus 4 attack families (DoS, Probe, R2L, U2R). Test set includes attack types unseen in training.
- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — modern (2017) labeled traffic. This project uses 32 flow-metadata features (packet sizes, inter-arrival times, TCP flag counts) that are computable live from packet headers, so the same models work on encrypted traffic.

## Limitations

- **NSL-KDD is dated.** Its traffic is from 1998; the NSL models are best read as a benchmark. Use `--schema cic` for live traffic.
- **CIC scores are optimistic.** See [Results](#cic-ids2017-stratified-30-hold-out) — a random split of one capture doesn't measure generalization to other networks.
- **File activity is counts only.** NSL-KDD provides file-activity *counts*, not filenames; affected-file paths would need a host-based source (auditd/Wazuh) or Zeek `files.log`.
- **Single-sensor, single-host.** The backend keeps live state in memory and JSONL files — designed for a home lab, not a fleet.
- **The API key reaches the browser.** See [Security](#security).

## License

[MIT](LICENSE)
