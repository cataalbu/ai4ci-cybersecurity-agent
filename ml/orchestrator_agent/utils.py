from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

import pandas as pd


def isoformat_ts(value: Any) -> str:
    ts = pd.to_datetime(value, utc=True, errors="coerce")
    if pd.isna(ts):
        return str(value)
    return ts.isoformat()


def compute_incident_key(
    window_start: Any, window_end: Any, label: str, source_ip: str
) -> str:
    payload = f"{isoformat_ts(window_start)}|{isoformat_ts(window_end)}|{label}|{source_ip}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
