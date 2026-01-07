import json
import os
from dataclasses import dataclass, field
from typing import List, Optional

import numpy as np
import pandas as pd
from joblib import dump, load
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# Deterministic, stable feature order used for training and scoring
FEATURE_COLUMNS: List[str] = [
    # Nginx
    "nginx_req_count",
    "nginx_unique_client_ips",
    "nginx_unique_paths",
    "nginx_2xx",
    "nginx_3xx",
    "nginx_4xx",
    "nginx_5xx",
    "nginx_4xx_rate",
    "nginx_5xx_rate",
    "nginx_top_path_count",
    # API
    "api_req_count",
    "api_unique_ips",
    "api_unique_users",
    "api_warn_count",
    "api_error_count",
    "api_latency_p50",
    "api_latency_p95",
    "api_latency_max",
    "api_4xx",
    "api_5xx",
    "api_4xx_rate",
    "api_5xx_rate",
    "api_login_fail_count",
    # UFW
    "ufw_event_count",
    "ufw_allow_count",
    "ufw_block_count",
    "ufw_block_rate",
    "ufw_unique_src_ips",
    "ufw_unique_dpt",
    "ufw_tcp_count",
    "ufw_udp_count",
    "ufw_top_dpt_count",
    # Cross-source
    "total_event_count",
    "unique_total_ips",
    "has_nginx",
    "has_api",
    "has_ufw",
]


def _to_utc_timestamps(events_df: pd.DataFrame) -> pd.Series:
    """Parse timestamps to timezone-aware UTC. Invalid rows become NaT."""
    ts = pd.to_datetime(events_df["timestamp"], utc=True, errors="coerce")
    return ts


def _assign_windows(
    timestamps: pd.Series, window_seconds: int
) -> pd.DataFrame:
    """Return a DataFrame with window_start and window_end columns."""
    window_start = timestamps.dt.floor(f"{window_seconds}s")
    window_end = window_start + pd.to_timedelta(window_seconds, unit="s")
    return pd.DataFrame({"window_start": window_start, "window_end": window_end})


def _safe_unique(series: Optional[pd.Series]) -> int:
    if series is None:
        return 0
    return int(series.dropna().nunique())


def _status_bucket_counts(df: pd.DataFrame) -> dict:
    """Return counts of status code classes for provided frame."""
    if "status" not in df.columns:
        return {2: 0, 3: 0, 4: 0, 5: 0}
    status = pd.to_numeric(df["status"], errors="coerce").dropna().astype(int)
    buckets = status // 100
    return {
        2: int((buckets == 2).sum()),
        3: int((buckets == 3).sum()),
        4: int((buckets == 4).sum()),
        5: int((buckets == 5).sum()),
    }


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def _top_count(series: Optional[pd.Series]) -> int:
    if series is None:
        return 0
    counts = series.dropna().value_counts()
    if counts.empty:
        return 0
    return int(counts.iloc[0])


def _latency_stats(series: Optional[pd.Series]) -> tuple[float, float, float]:
    if series is None:
        return 0.0, 0.0, 0.0
    lat = pd.to_numeric(series, errors="coerce").dropna()
    if lat.empty:
        return 0.0, 0.0, 0.0
    return (
        float(lat.quantile(0.50)),
        float(lat.quantile(0.95)),
        float(lat.max()),
    )


def _unique_total_ips(df: pd.DataFrame) -> int:
    ips = []
    if "client_ip" in df.columns:
        ips.append(df["client_ip"])
    if "src_ip" in df.columns:
        ips.append(df["src_ip"])
    if not ips:
        return 0
    combined = pd.concat(ips)
    return _safe_unique(combined)


def _api_unique_users(df: pd.DataFrame) -> int:
    for col in ("user", "username"):
        if col in df.columns:
            return _safe_unique(df[col])
    return 0


def build_feature_frame(
    events_df: pd.DataFrame, window_seconds: int = 60
) -> pd.DataFrame:
    """
    Return one row per window with window_start, window_end, and numeric features.
    """
    if "timestamp" not in events_df.columns:
        raise ValueError("events_df must contain a 'timestamp' column")

    timestamps = _to_utc_timestamps(events_df)
    # Drop rows with invalid timestamps to avoid NaT windows
    valid_mask = timestamps.notna()
    df = events_df.loc[valid_mask].copy()
    if df.empty:
        return pd.DataFrame(columns=["window_start", "window_end", *FEATURE_COLUMNS])

    windows = _assign_windows(timestamps.loc[valid_mask], window_seconds)
    df["window_start"] = windows["window_start"].values
    df["window_end"] = windows["window_end"].values

    rows = []
    for window_start, group in df.groupby("window_start", sort=True):
        window_end = group["window_end"].iloc[0]

        nginx_df = group[group["source"] == "nginx"]
        api_df = group[group["source"] == "api"]
        ufw_df = group[group["source"] == "ufw"]

        nginx_req_count = int(len(nginx_df))
        nginx_status_counts = _status_bucket_counts(nginx_df)
        nginx_unique_client_ips = _safe_unique(
            nginx_df["client_ip"] if "client_ip" in nginx_df else None
        )
        nginx_unique_paths = _safe_unique(
            nginx_df["path"] if "path" in nginx_df else None
        )
        nginx_top_path_count = _top_count(
            nginx_df["path"] if "path" in nginx_df else None
        )

        api_req_count = int(len(api_df))
        api_status_counts = _status_bucket_counts(api_df)
        api_unique_ips = _safe_unique(
            api_df["client_ip"] if "client_ip" in api_df else None
        )
        api_unique_users = _api_unique_users(api_df)
        api_warn_count = int(
            api_df["level"].str.upper().eq("WARN").sum()
            if "level" in api_df.columns
            else 0
        )
        api_error_count = int(
            api_df["level"].str.upper().eq("ERROR").sum()
            if "level" in api_df.columns
            else 0
        )
        latency_p50, latency_p95, latency_max = _latency_stats(
            api_df["latency_ms"] if "latency_ms" in api_df else None
        )
        api_login_fail_count = 0
        if "path" in api_df.columns and "status" in api_df.columns:
            path_match = api_df["path"].astype(str).str.contains(
                r"/login|/auth|/api/v1/login", regex=True, na=False
            )
            status_match = api_df["status"].isin([401, 403])
            api_login_fail_count = int((path_match & status_match).sum())

        ufw_event_count = int(len(ufw_df))
        ufw_allow_count = int(
            ufw_df["verdict"].str.upper().eq("ALLOW").sum()
            if "verdict" in ufw_df.columns
            else 0
        )
        ufw_block_count = int(
            ufw_df["verdict"].str.upper().eq("BLOCK").sum()
            if "verdict" in ufw_df.columns
            else 0
        )
        ufw_unique_src_ips = _safe_unique(
            ufw_df["src_ip"] if "src_ip" in ufw_df else None
        )
        ufw_unique_dpt = _safe_unique(ufw_df["dpt"] if "dpt" in ufw_df else None)
        ufw_tcp_count = int(
            ufw_df["proto"].str.upper().eq("TCP").sum()
            if "proto" in ufw_df.columns
            else 0
        )
        ufw_udp_count = int(
            ufw_df["proto"].str.upper().eq("UDP").sum()
            if "proto" in ufw_df.columns
            else 0
        )
        ufw_top_dpt_count = _top_count(ufw_df["dpt"] if "dpt" in ufw_df else None)

        row = {
            "window_start": window_start,
            "window_end": window_end,
            # Nginx
            "nginx_req_count": nginx_req_count,
            "nginx_unique_client_ips": nginx_unique_client_ips,
            "nginx_unique_paths": nginx_unique_paths,
            "nginx_2xx": nginx_status_counts[2],
            "nginx_3xx": nginx_status_counts[3],
            "nginx_4xx": nginx_status_counts[4],
            "nginx_5xx": nginx_status_counts[5],
            "nginx_4xx_rate": _rate(nginx_status_counts[4], nginx_req_count),
            "nginx_5xx_rate": _rate(nginx_status_counts[5], nginx_req_count),
            "nginx_top_path_count": nginx_top_path_count,
            # API
            "api_req_count": api_req_count,
            "api_unique_ips": api_unique_ips,
            "api_unique_users": api_unique_users,
            "api_warn_count": api_warn_count,
            "api_error_count": api_error_count,
            "api_latency_p50": latency_p50,
            "api_latency_p95": latency_p95,
            "api_latency_max": latency_max,
            "api_4xx": api_status_counts[4],
            "api_5xx": api_status_counts[5],
            "api_4xx_rate": _rate(api_status_counts[4], api_req_count),
            "api_5xx_rate": _rate(api_status_counts[5], api_req_count),
            "api_login_fail_count": api_login_fail_count,
            # UFW
            "ufw_event_count": ufw_event_count,
            "ufw_allow_count": ufw_allow_count,
            "ufw_block_count": ufw_block_count,
            "ufw_block_rate": _rate(ufw_block_count, ufw_event_count),
            "ufw_unique_src_ips": ufw_unique_src_ips,
            "ufw_unique_dpt": ufw_unique_dpt,
            "ufw_tcp_count": ufw_tcp_count,
            "ufw_udp_count": ufw_udp_count,
            "ufw_top_dpt_count": ufw_top_dpt_count,
            # Cross-source
            "total_event_count": int(len(group)),
            "unique_total_ips": _unique_total_ips(group),
            "has_nginx": int(nginx_req_count > 0),
            "has_api": int(api_req_count > 0),
            "has_ufw": int(ufw_event_count > 0),
        }
        rows.append(row)

    features_df = pd.DataFrame(rows)
    # Ensure all expected columns exist in order
    for col in FEATURE_COLUMNS:
        if col not in features_df.columns:
            features_df[col] = 0
    features_df = features_df[["window_start", "window_end", *FEATURE_COLUMNS]]
    return features_df.sort_values("window_start").reset_index(drop=True)


@dataclass
class IsolationForestDetector:
    window_seconds: int = 60
    n_estimators: int = 200
    random_state: int = 42
    threshold_percentile: float = 98.5
    contamination: str | float = "auto"
    model: Optional[IsolationForest] = field(init=False, default=None)
    scaler: Optional[StandardScaler] = field(init=False, default=None)
    threshold: Optional[float] = field(init=False, default=None)
    feature_columns: List[str] = field(init=False, default_factory=lambda: FEATURE_COLUMNS.copy())

    def fit(self, events_df: pd.DataFrame) -> None:
        """Train on healthy-only data."""
        features_df = build_feature_frame(events_df, self.window_seconds)
        X = features_df[self.feature_columns].astype(float)
        X = pd.DataFrame(np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0), columns=self.feature_columns)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            contamination=self.contamination,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)

        anomaly_scores = -self.model.score_samples(X_scaled)
        self.threshold = float(np.percentile(anomaly_scores, self.threshold_percentile))

    def score(self, events_df: pd.DataFrame) -> pd.DataFrame:
        """Return per-window anomaly_score and is_anomaly."""
        if self.model is None or self.scaler is None or self.threshold is None:
            raise RuntimeError("Model is not fitted. Call fit() or load() first.")

        features_df = build_feature_frame(events_df, self.window_seconds)
        X = features_df.reindex(columns=["window_start", "window_end", *self.feature_columns])
        X_features = X[self.feature_columns].astype(float)
        X_features = pd.DataFrame(
            np.nan_to_num(X_features, nan=0.0, posinf=0.0, neginf=0.0),
            columns=self.feature_columns,
        )

        X_scaled = self.scaler.transform(X_features)
        anomaly_scores = -self.model.score_samples(X_scaled)
        is_anomaly = anomaly_scores >= self.threshold

        result = pd.concat(
            [
                features_df[["window_start", "window_end"]].reset_index(drop=True),
                pd.DataFrame(X_features, columns=self.feature_columns).reset_index(drop=True),
            ],
            axis=1,
        )
        result["anomaly_score"] = anomaly_scores
        result["is_anomaly"] = is_anomaly
        return result

    def save(self, model_dir: str) -> None:
        """Persist model, scaler, and metadata."""
        if self.model is None or self.scaler is None or self.threshold is None:
            raise RuntimeError("Model is not fitted. Call fit() before save().")

        os.makedirs(model_dir, exist_ok=True)
        dump(self.model, os.path.join(model_dir, "model.joblib"))
        dump(self.scaler, os.path.join(model_dir, "scaler.joblib"))

        meta = {
            "window_seconds": self.window_seconds,
            "threshold": self.threshold,
            "threshold_percentile": self.threshold_percentile,
            "feature_columns": self.feature_columns,
            "model_params": {
                "n_estimators": self.n_estimators,
                "random_state": self.random_state,
                "contamination": self.contamination,
            },
        }
        with open(os.path.join(model_dir, "meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, model_dir: str) -> "IsolationForestDetector":
        """Restore a detector from disk."""
        meta_path = os.path.join(model_dir, "meta.json")
        model_path = os.path.join(model_dir, "model.joblib")
        scaler_path = os.path.join(model_dir, "scaler.joblib")

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        detector = cls(
            window_seconds=meta["window_seconds"],
            n_estimators=meta["model_params"]["n_estimators"],
            random_state=meta["model_params"]["random_state"],
            threshold_percentile=meta["threshold_percentile"],
            contamination=meta["model_params"]["contamination"],
        )
        detector.feature_columns = meta["feature_columns"]
        detector.threshold = meta["threshold"]
        detector.model = load(model_path)
        detector.scaler = load(scaler_path)
        return detector


if __name__ == "__main__":
    pass
