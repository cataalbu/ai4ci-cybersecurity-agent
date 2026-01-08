#!/usr/bin/env python
"""
Training script for the IsolationForest anomaly detector.

Loads training data, trains the model, and evaluates on test data.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd

# Add project root to Python path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from etl import run_etl
from ml.anomaly_detector.anomaly_detector import IsolationForestDetector


def load_manifest(manifest_path: str) -> pd.DataFrame:
    """Load manifest.jsonl file into a DataFrame."""
    records = []
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
    return pd.DataFrame(records)


def main() -> None:
    """Train anomaly detector and evaluate on test data."""
    root = Path(__file__).resolve().parent.parent.parent
    
    # Paths
    train_dir = root / "ml" / "training_data" / "anomaly_detector" / "train"
    test_dir = root / "ml" / "training_data" / "anomaly_detector" / "test"
    model_dir = root / "models" / "iforest"
    
    # Training parameters
    window_seconds = 60
    
    print("=" * 60)
    print("Training IsolationForest Anomaly Detector")
    print("=" * 60)
    
    # Load training data
    print(f"\nLoading training data from {train_dir}...")
    train_nginx = train_dir / "nginx_access.log"
    train_api = train_dir / "api_app.log"
    train_ufw = train_dir / "fw_ufw.log"
    
    train_files = {
        "nginx": train_nginx if train_nginx.exists() else None,
        "api": train_api if train_api.exists() else None,
        "ufw": train_ufw if train_ufw.exists() else None,
    }
    
    if not any(train_files.values()):
        raise FileNotFoundError(f"No training log files found in {train_dir}")
    
    print("Running ETL on training data...")
    etl_result = run_etl(
        nginx_path=str(train_files["nginx"]) if train_files["nginx"] else None,
        api_path=str(train_files["api"]) if train_files["api"] else None,
        ufw_path=str(train_files["ufw"]) if train_files["ufw"] else None,
        skip_disk_write=True,
    )
    
    print(f"ETL complete: {etl_result['total_rows']} records processed")
    for summary in etl_result["summaries"]:
        print(f"  {summary.file}: total={summary.total} ok={summary.ok} failed={summary.failed}")
    
    # Convert to DataFrame
    train_events = pd.DataFrame(etl_result["records"])
    if train_events.empty:
        raise ValueError("No training events found after ETL")
    
    print(f"\nTraining on {len(train_events)} events...")
    
    # Train the model
    detector = IsolationForestDetector(window_seconds=window_seconds)
    detector.fit(train_events)
    
    print(f"Training complete. Threshold: {detector.threshold:.4f}")
    
    # Save model
    print(f"\nSaving model to {model_dir}...")
    detector.save(str(model_dir))
    print("Model saved successfully.")
    
    # Evaluate on test data
    print("\n" + "=" * 60)
    print("Evaluating on test data")
    print("=" * 60)
    
    test_nginx = test_dir / "nginx_access.log"
    test_api = test_dir / "api_app.log"
    test_ufw = test_dir / "fw_ufw.log"
    test_manifest = test_dir / "manifest.jsonl"
    
    test_files = {
        "nginx": test_nginx if test_nginx.exists() else None,
        "api": test_api if test_api.exists() else None,
        "ufw": test_ufw if test_ufw.exists() else None,
    }
    
    if not any(test_files.values()):
        print(f"\nWarning: No test log files found in {test_dir}. Skipping evaluation.")
        return
    
    print(f"\nLoading test data from {test_dir}...")
    test_etl_result = run_etl(
        nginx_path=str(test_files["nginx"]) if test_files["nginx"] else None,
        api_path=str(test_files["api"]) if test_files["api"] else None,
        ufw_path=str(test_files["ufw"]) if test_files["ufw"] else None,
        skip_disk_write=True,
    )
    
    print(f"ETL complete: {test_etl_result['total_rows']} records processed")
    
    test_events = pd.DataFrame(test_etl_result["records"])
    if test_events.empty:
        print("No test events found. Skipping evaluation.")
        return
    
    # Score test data
    print(f"\nScoring {len(test_events)} test events...")
    scores = detector.score(test_events)
    
    total_windows = len(scores)
    total_anomalies = int(scores["is_anomaly"].sum())
    anomaly_rate = (total_anomalies / total_windows * 100) if total_windows > 0 else 0
    
    print(f"\nTest Results:")
    print(f"  Total windows: {total_windows}")
    print(f"  Anomalous windows: {total_anomalies} ({anomaly_rate:.2f}%)")
    print(f"  Normal windows: {total_windows - total_anomalies}")
    
    # If manifest exists, compare with ground truth
    if test_manifest.exists():
        print(f"\nLoading ground truth from {test_manifest}...")
        manifest_df = load_manifest(str(test_manifest))
        
        if not manifest_df.empty:
            # Merge scores with manifest
            manifest_df["window_start"] = pd.to_datetime(manifest_df["window_start"], utc=True)
            manifest_df["window_end"] = pd.to_datetime(manifest_df["window_end"], utc=True)
            scores["window_start"] = pd.to_datetime(scores["window_start"], utc=True)
            scores["window_end"] = pd.to_datetime(scores["window_end"], utc=True)
            
            merged = scores.merge(
                manifest_df[["window_start", "window_end", "is_attack", "scenario"]],
                on=["window_start", "window_end"],
                how="left",
            )
            
            if "is_attack" in merged.columns:
                merged["is_attack"] = merged["is_attack"].fillna(0).astype(int)
                true_positives = ((merged["is_anomaly"]) & (merged["is_attack"] == 1)).sum()
                false_positives = ((merged["is_anomaly"]) & (merged["is_attack"] == 0)).sum()
                true_negatives = ((~merged["is_anomaly"]) & (merged["is_attack"] == 0)).sum()
                false_negatives = ((~merged["is_anomaly"]) & (merged["is_attack"] == 1)).sum()
                
                precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
                recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
                f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
                accuracy = (true_positives + true_negatives) / len(merged) if len(merged) > 0 else 0
                
                print(f"\nGround Truth Comparison:")
                print(f"  True Positives: {true_positives}")
                print(f"  False Positives: {false_positives}")
                print(f"  True Negatives: {true_negatives}")
                print(f"  False Negatives: {false_negatives}")
                print(f"  Precision: {precision:.4f}")
                print(f"  Recall: {recall:.4f}")
                print(f"  F1 Score: {f1:.4f}")
                print(f"  Accuracy: {accuracy:.4f}")
    
    # Show top anomalies
    print(f"\nTop 10 windows by anomaly score:")
    top_anomalies = scores.nlargest(10, "anomaly_score")[
        ["window_start", "window_end", "anomaly_score", "is_anomaly"]
    ]
    print(top_anomalies.to_string(index=False))
    
    print("\n" + "=" * 60)
    print("Training and evaluation complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
