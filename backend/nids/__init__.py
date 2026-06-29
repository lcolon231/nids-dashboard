"""NIDS — Network Intrusion Detection System backend package.

Two-tier NIDS dashboard built on the NSL-KDD dataset:
  - data.py          download + verify NSL-KDD
  - preprocessing.py FeatureTransformer (fit + persist scaler/encoder)
  - models.py        train/persist GaussianNB, DecisionTree, KMeans
  - association.py   Apriori association rules (mlxtend)
  - evaluation.py    accuracy, precision, recall, F1

See SPEC.md for the regeneration pipeline.
"""

__version__ = "0.1.0"
