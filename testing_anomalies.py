#!/usr/bin/env python
"""
Quick helper to ETL the sample logs under ./logs and score anomalies
using the trained IsolationForest model in ./models/iforest.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

from etl.run import run_etl
from ml.anomaly_detector.anomaly_detector import IsolationForestDetector


def _load_events(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"output events file not found: {path}")
    if path.suffix.lower() == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path)


def main() -> int:
    root = Path(__file__).resolve().parent
    nginx_path = root / "logs/nginx_access.log"
    api_path = root / "logs/api_app.log"
    ufw_path = root / "logs/fw_ufw.log"
    out_path = root / "data/events_latest.parquet"
    model_dir = root / "models" / "iforest"

    print("Running ETL on ./logs ...")
    etl_result = run_etl(
        nginx_path=str(nginx_path),
        api_path=str(api_path),
        ufw_path=str(ufw_path),
        out_path=str(out_path),
    )
    print("ETL complete.")
    for summary in etl_result["summaries"]:
        print(
            f"{summary.file}: total={summary.total} ok={summary.ok} failed={summary.failed}"
        )
    events_path = Path(etl_result["output_path"])
    print(f"Normalized events written to: {events_path}")

    events = _load_events(events_path)
    if events.empty:
        print("No events to score; exiting.")
        return 0

    print(f"Loaded {len(events)} normalized events; scoring anomalies...")
    detector = IsolationForestDetector.load(str(model_dir))
    scores = detector.score(events)
    total_anomalies = int(scores["is_anomaly"].sum())
    print(f"Total windows: {len(scores)} | Anomalous windows: {total_anomalies}")

    top = (
        scores.sort_values("anomaly_score", ascending=False)[
            ["window_start", "window_end", "anomaly_score", "is_anomaly"]
        ]
        .head(10)
        .reset_index(drop=True)
    )
    print("\nTop 10 windows by anomaly_score:")
    print(top.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

