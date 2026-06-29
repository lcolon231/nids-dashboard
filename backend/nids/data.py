"""NSL-KDD dataset download + verification.

Phase 2 implements:
  - download(): fetch KDDTrain+.txt / KDDTest+.txt into data/raw/
  - load(split): read a split into a DataFrame with proper column names
  - verify(): assert row/col counts (train 125973x43, test 22544x43)

CLI: python -m nids.data download
"""
from __future__ import annotations

# Implemented in Phase 2.
