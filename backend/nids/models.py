"""Model training + persistence for NSL-KDD.

Phase 4 implements:
  - GaussianNB (binary)        -> data/processed/nb_binary.joblib
  - DecisionTreeClassifier     -> data/processed/dt_binary.joblib
  - KMeans sweep k=2..10 (inertia + silhouette on 10k sample),
    pick best k by silhouette -> kmeans.joblib + kmeans_sweep.json

Trained on KDDTrain+, evaluated on KDDTest+.
CLI: python -m nids.models train
"""
from __future__ import annotations

# Implemented in Phase 4.
