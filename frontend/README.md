# NIDS Dashboard — Frontend

Next.js 15 (App Router) + React 19 + Tailwind CSS 4 dashboard for the NIDS backend. Polls the FastAPI API and renders five panels:

| Panel | Component | Backend endpoints |
|-------|-----------|-------------------|
| Model performance | `MetricsPanel.tsx` | `/metrics` (toggle `binary`/`multiclass`, `nsl`/`cic`) |
| Dataset summary | `DatasetPanel.tsx` | `/dataset/summary` (toggle `train`/`test`) |
| Association rules | `RulesPanel.tsx` | `/rules` |
| Live feed | `LiveFeedPanel.tsx` | `/live/recent` |
| Anomalies | `AnomalyPanel.tsx` | `/anomalies/status`, `/anomalies/recent` |

All API calls go through the typed client in `lib/api.ts`.

## Run

```bash
npm install
npm run dev          # http://localhost:3000, expects the backend on :8000
```

Production: `npm run build && npm run start`.

## Configuration

Both variables are read at **build time** (`NEXT_PUBLIC_*` is inlined into the bundle), so set them before `npm run build` / `npm run dev`.

| Variable | Default | Purpose |
|----------|---------|---------|
| `NEXT_PUBLIC_API_URL` | `http://127.0.0.1:8000` | backend base URL |
| `NEXT_PUBLIC_NIDS_API_KEY` | — | sent as `X-API-Key` when the backend has `NIDS_API_KEY` set |

> **Note:** because `NEXT_PUBLIC_NIDS_API_KEY` is embedded in the client JavaScript, anyone who can load the dashboard can read the key. That's fine on a trusted LAN; don't expose the dashboard publicly with this setup.

## Checks

```bash
npm run lint
npx tsc --noEmit
npm run build
```

These run in CI on every pull request (`.github/workflows/ci.yml`).
