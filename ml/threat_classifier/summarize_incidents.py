#!/usr/bin/env python
"""
Run threat classification on a logs directory and then produce an LLM incident summary
per predicted (attack) window.

This is intended as the "post-classifier" summarization step.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

import pandas as pd

# Add project root to Python path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from etl import run_etl  # noqa: E402
from ml.incident_summarizer import SummarizerConfig, summarize_incident_window  # noqa: E402
from ml.threat_classifier.xgboost_classifier import predict_from_logs  # noqa: E402


def _iso(ts: Any) -> str:
    out = pd.to_datetime(ts, utc=True, errors="coerce")
    if pd.isna(out):
        return str(ts)
    return out.isoformat()


def main() -> int:
    ap = argparse.ArgumentParser(description="Summarize incidents after threat classification.")
    ap.add_argument("--log-dir", required=True, help="Directory containing nginx_access.log, api_app.log, fw_ufw.log")
    ap.add_argument("--window-seconds", type=int, default=60, help="Window size used by the classifier/features")
    ap.add_argument(
        "--model-dir",
        default=str(project_root / "models" / "xgb-threat"),
        help="Classifier model directory (contains model.json, label_encoder.json)",
    )
    ap.add_argument("--out", default="-", help="Output JSONL path (default: stdout)")
    ap.add_argument(
        "--min-proba",
        type=float,
        default=0.0,
        help="Minimum probability for predicted_label to include an incident (default: 0.0)",
    )
    ap.add_argument(
        "--include-healthy",
        action="store_true",
        help="Include windows predicted as 'healthy' (default: false)",
    )
    ap.add_argument(
        "--max-raw-lines",
        type=int,
        default=10,
        help="Max raw log lines to pass to the LLM as evidence (default: 10)",
    )
    args = ap.parse_args()

    log_dir = Path(args.log_dir)
    nginx_path = log_dir / "nginx_access.log"
    api_path = log_dir / "api_app.log"
    ufw_path = log_dir / "fw_ufw.log"

    preds_df = predict_from_logs(str(log_dir), args.window_seconds, args.model_dir)
    if preds_df.empty:
        print("[warn] no prediction windows produced (no events or empty logs)", file=sys.stderr)
        return 0

    etl_result = run_etl(
        nginx_path=str(nginx_path),
        api_path=str(api_path),
        ufw_path=str(ufw_path),
        skip_disk_write=True,
    )
    events_df = pd.DataFrame(etl_result.get("records", []))
    if events_df.empty:
        print("[warn] ETL produced no events; cannot summarize incidents", file=sys.stderr)
        return 0

    cfg = SummarizerConfig()

    out_fh = sys.stdout if args.out == "-" else open(args.out, "w", encoding="utf-8")
    try:
        for _, row in preds_df.iterrows():
            predicted_label = str(row.get("predicted_label", "")).strip()
            proba = row.get("proba")
            proba_dict: Dict[str, float] | None
            if isinstance(proba, dict):
                proba_dict = {str(k): float(v) for k, v in proba.items()}
            else:
                proba_dict = None

            if (not args.include_healthy) and predicted_label.lower() == "healthy":
                continue

            if proba_dict is not None and args.min_proba > 0:
                p = float(proba_dict.get(predicted_label, 0.0))
                if p < args.min_proba:
                    continue

            try:
                summary = summarize_incident_window(
                    predicted_label=predicted_label,
                    proba=proba_dict,
                    window_start=row.get("window_start"),
                    window_end=row.get("window_end"),
                    events_df=events_df,
                    cfg=cfg,
                    max_raw_lines=args.max_raw_lines,
                )
                rec: Dict[str, Any] = {
                    "window_start": _iso(row.get("window_start")),
                    "window_end": _iso(row.get("window_end")),
                    "predicted_label": predicted_label,
                    "proba": proba_dict,
                    "title": summary.title,
                    "description": summary.description,
                }
            except Exception as exc:
                rec = {
                    "window_start": _iso(row.get("window_start")),
                    "window_end": _iso(row.get("window_end")),
                    "predicted_label": predicted_label,
                    "proba": proba_dict,
                    "error": f"summarization_failed: {exc}",
                }

            out_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    finally:
        if out_fh is not sys.stdout:
            out_fh.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

