"""Association rule mining (Apriori) for NSL-KDD.

Phase 5 implements:
  - binarize features into boolean transaction format
  - apriori(min_support=0.01)
  - association_rules(min_confidence=0.7), sort by lift desc
  - save top 50 to data/processed/rules.csv
    columns: antecedents, consequents, support, confidence, lift

Transactions are built from the three categorical features plus two boolean
login flags, with the 5-category label (normal/dos/probe/r2l/u2r) as an item.
Rules are filtered to those whose consequent is a single label item, so each
rule reads as "traffic pattern -> class", e.g.
{service=http, flag=SF} -> {label=normal}.

CLI: python -m nids.association build
"""
from __future__ import annotations

import sys

import pandas as pd
from mlxtend.frequent_patterns import apriori, association_rules

from nids import data
from nids.preprocessing import ATTACK_CATEGORY, PROCESSED_DIR

RULES_PATH = PROCESSED_DIR / "rules.csv"

MIN_SUPPORT = 0.01
MIN_CONFIDENCE = 0.7
MAX_LEN = 4  # antecedent items + the label consequent
TOP_N = 50

# Items: the 3 categoricals, 2 boolean login flags, and the label category.
ITEM_COLUMNS = ["protocol_type", "service", "flag", "logged_in", "is_guest_login"]
LABEL_PREFIX = "label="


def build_transactions(df: pd.DataFrame) -> pd.DataFrame:
    """One-hot boolean item matrix: feature=value columns + label=category."""
    items = pd.DataFrame(index=df.index)
    for col in ITEM_COLUMNS:
        dummies = pd.get_dummies(df[col].astype(str), prefix=col, prefix_sep="=")
        items = pd.concat([items, dummies.astype(bool)], axis=1)
    category = df["label"].map(ATTACK_CATEGORY)
    label_dummies = pd.get_dummies(category, prefix="label", prefix_sep="=")
    return pd.concat([items, label_dummies.astype(bool)], axis=1)


def mine_rules(transactions: pd.DataFrame) -> pd.DataFrame:
    """Apriori -> top rules with a single label=<category> consequent.

    min_confidence=0.7, sorted by lift descending, top 50 kept.
    """
    frequent = apriori(
        transactions, min_support=MIN_SUPPORT, use_colnames=True, max_len=MAX_LEN
    )
    rules = association_rules(
        frequent,
        num_itemsets=len(transactions),  # required by mlxtend >= 0.23.3
        metric="confidence",
        min_threshold=MIN_CONFIDENCE,
    )

    # Keep rules that conclude in exactly one label item, with no label items
    # in the antecedent (pattern -> class, not class -> pattern).
    is_label = lambda s: s.startswith(LABEL_PREFIX)  # noqa: E731
    mask = rules["consequents"].map(
        lambda c: len(c) == 1 and all(is_label(i) for i in c)
    ) & rules["antecedents"].map(lambda a: not any(is_label(i) for i in a))
    rules = rules[mask].copy()

    rules["antecedents"] = rules["antecedents"].map(lambda s: ", ".join(sorted(s)))
    rules["consequents"] = rules["consequents"].map(lambda s: ", ".join(sorted(s)))
    out = rules[["antecedents", "consequents", "support", "confidence", "lift"]]
    return out.sort_values("lift", ascending=False).head(TOP_N).reset_index(drop=True)


def build() -> pd.DataFrame:
    """Full Phase 5 pipeline: KDDTrain+ -> rules.csv."""
    df = data.load("train")
    transactions = build_transactions(df)
    print(f"[ok  ] transactions: {transactions.shape[0]} rows x {transactions.shape[1]} items")
    rules = mine_rules(transactions)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    rules.to_csv(RULES_PATH, index=False)
    print(f"[ok  ] {len(rules)} rules -> {RULES_PATH}")
    return rules


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "build"
    if cmd == "build":
        build()
        return 0
    print(f"unknown command {cmd!r}; usage: python -m nids.association build")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
