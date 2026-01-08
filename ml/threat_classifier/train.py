#!/usr/bin/env python
"""
Training script for the XGBoost threat classifier.

Loads training data, trains the model, and evaluates on test data.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from ml.threat_classifier.xgboost_classifier import (
    load_split,
    train_and_evaluate,
)


def main() -> None:
    """Train threat classifier and evaluate on test data."""
    root = Path(__file__).resolve().parent.parent.parent
    
    # Paths
    train_dir = root / "ml" / "training_data" / "threat_classifier" / "train"
    val_dir = root / "ml" / "training_data" / "threat_classifier" / "val"
    test_dir = root / "ml" / "training_data" / "threat_classifier" / "test"
    model_dir = root / "models" / "xgb-threat"
    
    print("=" * 60)
    print("Training XGBoost Threat Classifier")
    print("=" * 60)
    
    # Load training data
    print(f"\nLoading training data from {train_dir}...")
    if not train_dir.exists():
        raise FileNotFoundError(f"Training directory not found: {train_dir}")
    
    train_manifest = train_dir / "manifest.jsonl"
    if not train_manifest.exists():
        raise FileNotFoundError(f"Training manifest not found: {train_manifest}")
    
    train_split = load_split(str(train_dir), "train")
    window_seconds = train_split.window_seconds
    
    print(f"Loaded {len(train_split.features)} training samples")
    print(f"Window size: {window_seconds} seconds")
    print(f"Classes: {train_split.class_counts}")
    
    # Load validation data if available
    val_split = None
    if val_dir.exists():
        val_manifest = val_dir / "manifest.jsonl"
        if val_manifest.exists():
            print(f"\nLoading validation data from {val_dir}...")
            val_split = load_split(str(val_dir), "val", window_seconds)
            print(f"Loaded {len(val_split.features)} validation samples")
            print(f"Classes: {val_split.class_counts}")
        else:
            print(f"\nNo validation manifest found in {val_dir}, skipping validation split.")
    else:
        print(f"\nValidation directory not found: {val_dir}, skipping validation split.")
    
    # Load test data
    print(f"\nLoading test data from {test_dir}...")
    if not test_dir.exists():
        raise FileNotFoundError(f"Test directory not found: {test_dir}")
    
    test_manifest = test_dir / "manifest.jsonl"
    if not test_manifest.exists():
        raise FileNotFoundError(f"Test manifest not found: {test_manifest}")
    
    test_split = load_split(str(test_dir), "test", window_seconds)
    print(f"Loaded {len(test_split.features)} test samples")
    print(f"Classes: {test_split.class_counts}")
    
    # Train the model
    print("\n" + "=" * 60)
    print("Training model...")
    print("=" * 60)
    
    model, label_encoder, metrics = train_and_evaluate(
        train_split=train_split,
        val_split=val_split,
        test_split=test_split,
        model_dir=str(model_dir),
        window_seconds=window_seconds,
    )
    
    print(f"\nModel saved to {model_dir}")
    
    # Print metrics
    print("\n" + "=" * 60)
    print("Training Metrics")
    print("=" * 60)
    if "train" in metrics:
        train_metrics = metrics["train"]
        print(f"\nTrain Set:")
        print(f"  Accuracy: {train_metrics.get('accuracy', 0):.4f}")
        print(f"  Macro F1: {train_metrics.get('macro_f1', 0):.4f}")
        print(f"  Balanced Accuracy: {train_metrics.get('balanced_accuracy', 0):.4f}")
        if "per_class_f1" in train_metrics:
            print(f"  Per-class F1:")
            for class_name, f1_score in train_metrics["per_class_f1"].items():
                print(f"    {class_name}: {f1_score:.4f}")
    
    if val_split and "val" in metrics:
        val_metrics = metrics["val"]
        print(f"\nValidation Set:")
        print(f"  Accuracy: {val_metrics.get('accuracy', 0):.4f}")
        print(f"  Macro F1: {val_metrics.get('macro_f1', 0):.4f}")
        print(f"  Balanced Accuracy: {val_metrics.get('balanced_accuracy', 0):.4f}")
        if "per_class_f1" in val_metrics:
            print(f"  Per-class F1:")
            for class_name, f1_score in val_metrics["per_class_f1"].items():
                print(f"    {class_name}: {f1_score:.4f}")
    
    if "test" in metrics:
        test_metrics = metrics["test"]
        print(f"\nTest Set:")
        print(f"  Accuracy: {test_metrics.get('accuracy', 0):.4f}")
        print(f"  Macro F1: {test_metrics.get('macro_f1', 0):.4f}")
        print(f"  Balanced Accuracy: {test_metrics.get('balanced_accuracy', 0):.4f}")
        if "top_1_accuracy" in test_metrics:
            print(f"  Top-1 Accuracy: {test_metrics.get('top_1_accuracy', 0):.4f}")
        if "top_3_accuracy" in test_metrics:
            print(f"  Top-3 Accuracy: {test_metrics.get('top_3_accuracy', 0):.4f}")
        if "per_class_f1" in test_metrics:
            print(f"  Per-class F1:")
            for class_name, f1_score in test_metrics["per_class_f1"].items():
                print(f"    {class_name}: {f1_score:.4f}")
        if "support" in test_metrics:
            print(f"  Per-class Support:")
            for class_name, support in test_metrics["support"].items():
                print(f"    {class_name}: {support}")
    
    # Save metrics summary
    metrics_file = model_dir / "metrics_summary.json"
    print(f"\nSaving metrics summary to {metrics_file}...")
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, default=str)
    
    print("\n" + "=" * 60)
    print("Training and evaluation complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
