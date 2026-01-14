from __future__ import annotations

from typing import Dict, List, Optional, TypedDict


class OffsetEntry(TypedDict):
    path: str
    pos_bytes: int
    last_size: int
    last_mtime: float


OffsetsState = Dict[str, OffsetEntry]


class OrchestratorState(TypedDict, total=False):
    batch_id: str
    batch_dir: str
    batch_bytes: int
    batch_lines: int
    next_offsets: OffsetsState
    events_df_path: str
    events_df_summary: Dict[str, object]
    anomaly_windows: List[Dict[str, object]]
    anomaly_any: bool
    threat_predictions: List[Dict[str, object]]
    suspicious_windows: List[Dict[str, object]]
    incident_summaries: List[Dict[str, object]]
    incident_payloads: List[Dict[str, object]]
    incident_create_results: List[Dict[str, object]]
    errors: List[str]
    metrics: Dict[str, object]
    no_new_data: bool
