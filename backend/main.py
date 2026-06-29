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

# Implemented in Phase 6 (and Phase 9 for /score/live).
