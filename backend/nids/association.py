"""Association rule mining (Apriori) for NSL-KDD.

Phase 5 implements:
  - binarize features into boolean transaction format
  - apriori(min_support=0.01)
  - association_rules(min_confidence=0.7), sort by lift desc
  - save top 50 to data/processed/rules.csv
    columns: antecedents, consequents, support, confidence, lift

CLI: python -m nids.association build
"""
from __future__ import annotations

# Implemented in Phase 5.
