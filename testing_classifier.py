#!/usr/bin/env python
"""
Quick helper to run the trained XGBoost threat classifier on a logs split
and summarize predictions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from ml.threat_classifier.xgboost_classifier import predict_from_logs


def main() -> int:
    root = Path(__file__).resolve().parent
    logs_dir = root / "logs" / "test"  # change to "val" or other split if desired
    model_dir = root / "models" / "xgb-threat"
    meta_path = model_dir / "meta.json"

    if not meta_path.exists():
        print(f"Model metadata not found: {meta_path}")
        return 1
    if not logs_dir.exists():
        print(f"Logs directory not found: {logs_dir}")
        return 1

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    window_seconds = int(meta.get("window_seconds", 60))

    print(f"Running classifier on {logs_dir} with window_seconds={window_seconds} ...")
    metrics = meta.get("metrics", {})
    for split in ("train", "val", "test"):
        if split in metrics:
            acc = metrics[split].get("accuracy")
            print(f"{split} accuracy: {acc}")
    preds = predict_from_logs(str(logs_dir), window_seconds=window_seconds, model_dir=str(model_dir))

    if preds.empty:
        print("No events/windows to score; exiting.")
        return 0

    print(f"Total windows scored: {len(preds)}")
    counts = preds["predicted_label"].value_counts().rename_axis("label").reset_index(name="count")
    print("\nPredicted label counts:")
    print(counts.to_string(index=False))

    top = preds.copy()
    top["top_prob"] = top["proba"].apply(lambda d: max(d.values()) if isinstance(d, dict) else None)
    top = top.sort_values("top_prob", ascending=False)[
        ["window_start", "window_end", "predicted_label", "top_prob"]
    ].head(10)
    print("\nTop 10 windows by predicted probability:")
    print(top.to_string(index=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


