from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    top_k_accuracy_score,
)
from sklearn.preprocessing import LabelEncoder

from etl import run_etl
from ml.anomaly_detector.anomaly_detector import FEATURE_COLUMNS, build_feature_frame


# ----------------------------
# Window normalization helpers
# ----------------------------


def normalize_window(ts: pd.Timestamp | str | datetime, window_seconds: int) -> Tuple[pd.Timestamp, pd.Timestamp]:
    """Normalize an input timestamp to window_start (floor) and window_end in UTC."""
    ts_parsed = pd.to_datetime(ts, utc=True, errors="coerce")
    if pd.isna(ts_parsed):
        raise ValueError(f"Invalid timestamp: {ts}")
    window_start = ts_parsed.floor(f"{window_seconds}s")
    window_end = window_start + pd.to_timedelta(window_seconds, unit="s")
    return window_start, window_end


def infer_window_seconds(manifest_df: pd.DataFrame) -> int:
    """Infer window size from manifest by mode of successive start diffs."""
    starts = pd.to_datetime(manifest_df["window_start"], utc=True, errors="coerce")
    diffs = starts.sort_values().diff().dropna().dt.total_seconds()
    if diffs.empty:
        return 60
    return int(diffs.mode().iloc[0])


# ----------------------------
# Data loading
# ----------------------------


def load_manifest(manifest_path: str, window_seconds: Optional[int] = None) -> Tuple[pd.DataFrame, int]:
    records: List[dict] = []
    with open(manifest_path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            entry = json.loads(line)
            records.append(entry)
    manifest_df = pd.DataFrame(records)
    if "window_start" not in manifest_df or manifest_df.empty:
        raise ValueError(f"Manifest missing window_start: {manifest_path}")

    if window_seconds is None:
        window_seconds = infer_window_seconds(manifest_df)

    starts, ends = [], []
    for ts in manifest_df["window_start"]:
        ws, we = normalize_window(ts, window_seconds)
        starts.append(ws)
        ends.append(we)
    manifest_df["window_start"] = starts
    manifest_df["window_end"] = ends
    return manifest_df, window_seconds


def _etl_split(split_dir: str) -> pd.DataFrame:
    nginx = os.path.join(split_dir, "nginx_access.log")
    api = os.path.join(split_dir, "api_app.log")
    ufw = os.path.join(split_dir, "fw_ufw.log")
    result = run_etl(nginx_path=nginx, api_path=api, ufw_path=ufw, skip_disk_write=True)
    df = pd.DataFrame(result["records"])
    if df.empty:
        return df
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df[df["timestamp"].notna()]
    return df


# ----------------------------
# Feature building & alignment
# ----------------------------


def _ensure_feature_columns(features_df: pd.DataFrame) -> pd.DataFrame:
    for col in FEATURE_COLUMNS:
        if col not in features_df.columns:
            features_df[col] = 0
    return features_df[["window_start", "window_end", *FEATURE_COLUMNS]].copy()


def build_features_for_manifest(
    events_df: pd.DataFrame, manifest_df: pd.DataFrame, window_seconds: int
) -> pd.DataFrame:
    """Compute features and align to manifest windows, zero-filling missing ones."""
    feature_df = build_feature_frame(events_df, window_seconds)
    # Ensure window columns are tz-aware UTC to match manifest
    for col in ("window_start", "window_end"):
        if col in feature_df.columns:
            feature_df[col] = pd.to_datetime(feature_df[col], utc=True, errors="coerce")
    feature_df = _ensure_feature_columns(feature_df)

    # Align on canonical windows
    manifest_windows = manifest_df[["window_start", "window_end"]].copy()
    manifest_windows["window_start"] = pd.to_datetime(manifest_windows["window_start"], utc=True)
    manifest_windows["window_end"] = pd.to_datetime(manifest_windows["window_end"], utc=True)
    merged = manifest_windows.merge(
        feature_df,
        on=["window_start", "window_end"],
        how="left",
        suffixes=("", ""),
    )
    merged = _ensure_feature_columns(merged)

    # Zero-fill missing feature rows
    feature_cols_only = FEATURE_COLUMNS
    merged[feature_cols_only] = merged[feature_cols_only].fillna(0)
    return merged


# ----------------------------
# Class weights & metrics
# ----------------------------


def compute_class_weights(labels: Iterable[int]) -> Dict[int, float]:
    series = pd.Series(labels)
    counts = series.value_counts()
    total = len(series)
    num_classes = len(counts)
    weights = {}
    for cls, cnt in counts.items():
        weights[int(cls)] = total / (num_classes * cnt) if cnt > 0 else 1.0
    return weights


def metrics_for_split(
    y_true: np.ndarray,
    proba: np.ndarray,
    label_encoder: LabelEncoder,
    top_k: Tuple[int, ...] = (1, 3),
) -> dict:
    preds = proba.argmax(axis=1)
    labels = label_encoder.classes_
    result = {
        "accuracy": float(accuracy_score(y_true, preds)),
        "macro_f1": float(f1_score(y_true, preds, average="macro")),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, preds)),
        "confusion_matrix": confusion_matrix(y_true, preds).tolist(),
        "per_class_f1": {
            str(labels[i]): float(f1_score(y_true, preds, labels=[i], average="macro"))
            for i in range(len(labels))
        },
        "support": {str(labels[i]): int((y_true == i).sum()) for i in range(len(labels))},
    }
    for k in top_k:
        try:
            result[f"top_{k}_accuracy"] = float(top_k_accuracy_score(y_true, proba, k=k))
        except Exception:
            result[f"top_{k}_accuracy"] = None
    return result


# ----------------------------
# Persistence helpers
# ----------------------------


def _sha256_files(paths: List[str]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        if not os.path.exists(path):
            continue
        with open(path, "rb") as f:
            digest.update(f.read())
    return digest.hexdigest()


def _feature_checksum() -> str:
    joined = ",".join(FEATURE_COLUMNS)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def save_artifacts(
    out_dir: str,
    model: xgb.XGBClassifier,
    label_encoder: LabelEncoder,
    meta: dict,
) -> None:
    os.makedirs(out_dir, exist_ok=True)
    if not hasattr(model, "_estimator_type"):
        # Older xgboost sklearn wrappers may miss this attribute; set for save_model.
        model._estimator_type = "classifier"  # type: ignore[attr-defined]
    model.save_model(os.path.join(out_dir, "model.json"))
    with open(os.path.join(out_dir, "label_encoder.json"), "w", encoding="utf-8") as f:
        json.dump({"classes": label_encoder.classes_.tolist()}, f, indent=2)
    with open(os.path.join(out_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, default=str)


# ----------------------------
# Dataset preparation
# ----------------------------


@dataclass
class SplitData:
    features: pd.DataFrame
    labels: pd.Series
    is_attack: pd.Series
    manifest: pd.DataFrame
    class_counts: Dict[str, int]
    window_seconds: int


def load_split(split_dir: str, split_name: str, window_seconds: Optional[int] = None) -> SplitData:
    manifest_path = os.path.join(split_dir, "manifest.jsonl")
    manifest_df, inferred_window = load_manifest(manifest_path, window_seconds)
    window_seconds = window_seconds or inferred_window

    events_df = _etl_split(split_dir)
    if not events_df.empty:
        min_ws, max_we = manifest_df["window_start"].min(), manifest_df["window_end"].max()
        events_df = events_df[
            (events_df["timestamp"] >= min_ws) & (events_df["timestamp"] < max_we)
        ]

    feature_df = build_features_for_manifest(events_df, manifest_df, window_seconds)
    labeled = manifest_df[["window_start", "window_end", "scenario", "is_attack"]].merge(
        feature_df, on=["window_start", "window_end"], how="left"
    )
    labeled[FEATURE_COLUMNS] = labeled[FEATURE_COLUMNS].fillna(0)

    labels = labeled["scenario"]
    is_attack = labeled["is_attack"] if "is_attack" in labeled else pd.Series([None] * len(labels))
    class_counts = labels.value_counts().to_dict()

    return SplitData(
        features=labeled[FEATURE_COLUMNS],
        labels=labels,
        is_attack=is_attack,
        manifest=labeled[["window_start", "window_end", "scenario", "is_attack"]],
        class_counts=class_counts,
        window_seconds=window_seconds,
    )


# ----------------------------
# Training & evaluation
# ----------------------------


def train_and_evaluate(
    train_split: SplitData,
    val_split: Optional[SplitData],
    test_split: Optional[SplitData],
    model_dir: str,
    window_seconds: int,
    hyperparams: Optional[dict] = None,
):
    hyperparams = hyperparams or {}
    default_params = {
        "n_estimators": 500,
        "max_depth": 6,
        "learning_rate": 0.05,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "reg_lambda": 1.0,
        "min_child_weight": 1,
        "objective": "multi:softprob",
        "eval_metric": "mlogloss",
        "tree_method": "hist",
    }
    params = {**default_params, **hyperparams}

    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform(train_split.labels)
    X_train = train_split.features.to_numpy(dtype=float)

    # Sample weights for multi-class imbalance
    weight_map = compute_class_weights(y_train)
    sample_weight = np.array([weight_map[int(y)] for y in y_train], dtype=float)

    eval_set = None
    if val_split:
        y_val = label_encoder.transform(val_split.labels)
        X_val = val_split.features.to_numpy(dtype=float)
        eval_set = [(X_val, y_val)]

    model = xgb.XGBClassifier(**params)
    fit_kwargs = {
        "sample_weight": sample_weight,
    }
    if eval_set:
        fit_kwargs["eval_set"] = eval_set
        fit_kwargs["verbose"] = False

    # Older xgboost versions may not support callbacks/early stopping in sklearn API; keep fit simple.
    model.fit(X_train, y_train, **fit_kwargs)

    metrics = {"train": {}}
    train_proba = model.predict_proba(X_train)
    metrics["train"] = metrics_for_split(y_train, train_proba, label_encoder)

    for split_name, split in (("val", val_split), ("test", test_split)):
        if not split:
            continue
        y_true = label_encoder.transform(split.labels)
        X = split.features.to_numpy(dtype=float)
        proba = model.predict_proba(X)
        metrics[split_name] = metrics_for_split(y_true, proba, label_encoder)

    meta = {
        "window_seconds": window_seconds,
        "feature_columns": FEATURE_COLUMNS,
        "feature_checksum": _feature_checksum(),
        "class_counts": {
            "train": train_split.class_counts,
            "val": val_split.class_counts if val_split else {},
            "test": test_split.class_counts if test_split else {},
        },
        "hyperparams": model.get_params(),
        "xgboost_version": xgb.__version__,
        "python_version": sys.version,
        "data_hash": _sha256_files(
            [
                os.path.join(Path(model_dir).parent, "train", "manifest.jsonl"),
                os.path.join(Path(model_dir).parent, "val", "manifest.jsonl"),
                os.path.join(Path(model_dir).parent, "test", "manifest.jsonl"),
            ]
        ),
        "metrics": metrics,
    }

    save_artifacts(model_dir, model, label_encoder, meta)
    return model, label_encoder, metrics


# ----------------------------
# Inference
# ----------------------------


def predict_from_logs(log_dir: str, window_seconds: int, model_dir: str) -> pd.DataFrame:
    model = xgb.XGBClassifier()
    if not hasattr(model, "_estimator_type"):
        model._estimator_type = "classifier"  # type: ignore[attr-defined]
    model.load_model(os.path.join(model_dir, "model.json"))
    with open(os.path.join(model_dir, "label_encoder.json"), "r", encoding="utf-8") as f:
        enc_data = json.load(f)
    label_encoder = LabelEncoder()
    label_encoder.classes_ = np.array(enc_data["classes"])

    events_df = _etl_split(log_dir)
    if events_df.empty:
        return pd.DataFrame(columns=["window_start", "window_end", "predicted_label", "proba"])

    features_df = build_feature_frame(events_df, window_seconds)
    features_df = _ensure_feature_columns(features_df)
    X = features_df[FEATURE_COLUMNS].to_numpy(dtype=float)
    proba = model.predict_proba(X)
    preds = label_encoder.inverse_transform(proba.argmax(axis=1))
    proba_dicts = [dict(zip(label_encoder.classes_, row)) for row in proba]
    return pd.DataFrame(
        {
            "window_start": features_df["window_start"],
            "window_end": features_df["window_end"],
            "predicted_label": preds,
            "proba": proba_dicts,
        }
    )



