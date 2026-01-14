from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import pandas as pd
import xgboost as xgb
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from sklearn.preprocessing import LabelEncoder

from etl import run_etl
from ml.anomaly_detector.anomaly_detector import IsolationForestDetector
from ml.incident_summarizer.summarizer import (
    SummarizerConfig,
    _extract_evidence,
    summarize_incident_window,
)
from ml.threat_classifier.xgboost_classifier import (
    FEATURE_COLUMNS,
    _ensure_feature_columns,
    build_feature_frame,
)

from .batch_materialize import materialize_batch
from .backend_client import create_incident
from .config import (
    ANOMALY_MODEL_DIR,
    ASSET_IP,
    BATCHES_DIR,
    BATCH_TARGET_LINES,
    LOG_DIR,
    MAX_RAW_LINES,
    READ_CHUNK_BYTES,
    THREAT_MODEL_DIR,
    USE_LLM_REFINEMENT,
    WINDOW_SECONDS,
)
from .log_tail import read_batch
from .state import OrchestratorState
from .state_store import load_dedupe, save_dedupe, save_offsets
from .utils import compute_incident_key, isoformat_ts


def _batch_paths() -> Dict[str, Path]:
    return {
        "nginx": LOG_DIR / "nginx_access.log",
        "api": LOG_DIR / "api_app.log",
        "ufw": LOG_DIR / "fw_ufw.log",
    }


def _events_path(batch_dir: Path) -> Path:
    return batch_dir / "events.pkl"


def _load_events_df(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    return pd.read_pickle(path)


def _events_summary(events_df: pd.DataFrame) -> Dict[str, object]:
    if events_df.empty:
        return {"total": 0}
    ts = pd.to_datetime(events_df["timestamp"], utc=True, errors="coerce")
    summary = {
        "total": int(len(events_df)),
        "start": isoformat_ts(ts.min()),
        "end": isoformat_ts(ts.max()),
    }
    for col in ("client_ip", "src_ip", "dst_ip", "dpt"):
        if col in events_df.columns:
            top = events_df[col].dropna().astype(str).value_counts().head(3)
            summary[f"top_{col}"] = top.to_dict()
    return summary


def _filter_window(events_df: pd.DataFrame, window_start: object, window_end: object) -> pd.DataFrame:
    if events_df.empty:
        return events_df
    ts = pd.to_datetime(events_df["timestamp"], utc=True, errors="coerce")
    ws = pd.to_datetime(window_start, utc=True, errors="coerce")
    we = pd.to_datetime(window_end, utc=True, errors="coerce")
    return events_df.loc[(ts >= ws) & (ts < we)].copy()


def _top_value(series: pd.Series) -> Optional[str]:
    if series is None:
        return None
    counts = series.dropna().astype(str).value_counts()
    if counts.empty:
        return None
    return str(counts.index[0])


def _severity_from_inputs(confidence: Optional[int], anomaly_score: Optional[float]) -> int:
    base = confidence if confidence is not None else 50
    boost = 10 if anomaly_score is not None else 0
    return max(0, min(100, int(base + boost)))


def read_batch_node(state: OrchestratorState) -> OrchestratorState:
    print("[orchestrator] read_batch: start")
    paths = _batch_paths()
    data_by_file, next_offsets, total_bytes, total_lines = read_batch(
        paths,
        state.get("next_offsets", {}),
        BATCH_TARGET_LINES,
        READ_CHUNK_BYTES,
    )
    if total_bytes <= 0:
        return {"no_new_data": True}

    batch_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + f"-{os.urandom(3).hex()}"
    batch_dir = BATCHES_DIR / batch_id
    materialize_batch(batch_dir, data_by_file)
    print(
        "[orchestrator] read_batch: batch ready "
        f"id={batch_id} bytes={total_bytes} lines={total_lines}"
    )

    return {
        "batch_id": batch_id,
        "batch_dir": str(batch_dir),
        "batch_bytes": total_bytes,
        "batch_lines": total_lines,
        "next_offsets": next_offsets,
        "no_new_data": False,
    }


def run_etl_once_node(state: OrchestratorState) -> OrchestratorState:
    print("[orchestrator] run_etl_once: start")
    batch_dir = state.get("batch_dir")
    if not batch_dir:
        return {}
    log_dir = Path(batch_dir)
    result = run_etl(
        nginx_path=str(log_dir / "nginx_access.log"),
        api_path=str(log_dir / "api_app.log"),
        ufw_path=str(log_dir / "fw_ufw.log"),
        skip_disk_write=True,
    )
    events_df = pd.DataFrame(result.get("records", []))
    events_path = _events_path(log_dir)
    events_df.to_pickle(events_path)
    print(f"[orchestrator] run_etl_once: events={len(events_df)}")
    return {
        "events_df_path": str(events_path),
        "events_df_summary": _events_summary(events_df),
    }


def run_anomaly_detector_node(state: OrchestratorState) -> OrchestratorState:
    print("[orchestrator] run_anomaly_detector: start")
    events_df = _load_events_df(Path(state.get("events_df_path", "")))
    if events_df.empty:
        print("[orchestrator] run_anomaly_detector: no events")
        return {"anomaly_any": False, "anomaly_windows": []}

    detector = IsolationForestDetector.load(str(ANOMALY_MODEL_DIR))
    scores_df = detector.score(events_df)
    anomalies = scores_df[scores_df["is_anomaly"] == True]  # noqa: E712
    windows = [
        {
            "window_start": isoformat_ts(row["window_start"]),
            "window_end": isoformat_ts(row["window_end"]),
            "anomaly_score": float(row["anomaly_score"]),
        }
        for _, row in anomalies.iterrows()
    ]
    print(f"[orchestrator] run_anomaly_detector: anomalies={len(windows)}")
    return {"anomaly_any": len(windows) > 0, "anomaly_windows": windows}


def run_threat_classifier_node(state: OrchestratorState) -> OrchestratorState:
    print("[orchestrator] run_threat_classifier: start")
    events_df = _load_events_df(Path(state.get("events_df_path", "")))
    if events_df.empty:
        print("[orchestrator] run_threat_classifier: no events")
        return {"threat_predictions": [], "suspicious_windows": []}

    model = xgb.XGBClassifier()
    if not hasattr(model, "_estimator_type"):
        model._estimator_type = "classifier"  # type: ignore[attr-defined]
    model.load_model(str(THREAT_MODEL_DIR / "model.json"))
    with open(THREAT_MODEL_DIR / "label_encoder.json", "r", encoding="utf-8") as handle:
        enc_data = json.load(handle)
    label_encoder = LabelEncoder()
    label_encoder.classes_ = np.array(enc_data["classes"])

    features_df = build_feature_frame(events_df, WINDOW_SECONDS)
    features_df = _ensure_feature_columns(features_df)
    if features_df.empty:
        print("[orchestrator] run_threat_classifier: no feature windows")
        return {"threat_predictions": [], "suspicious_windows": []}

    X = features_df[FEATURE_COLUMNS].to_numpy(dtype=float)
    proba = model.predict_proba(X)
    preds = label_encoder.inverse_transform(proba.argmax(axis=1))
    proba_dicts = [
        {str(label): float(score) for label, score in zip(label_encoder.classes_, row)}
        for row in proba
    ]
    preds_df = pd.DataFrame(
        {
            "window_start": features_df["window_start"],
            "window_end": features_df["window_end"],
            "predicted_label": preds,
            "proba": proba_dicts,
        }
    )
    preds_list = [
        {
            "window_start": isoformat_ts(row["window_start"]),
            "window_end": isoformat_ts(row["window_end"]),
            "predicted_label": str(row["predicted_label"]),
            "proba": row["proba"],
        }
        for _, row in preds_df.iterrows()
    ]
    suspicious = [
        item for item in preds_list if str(item["predicted_label"]).lower() != "healthy"
    ]
    print(
        "[orchestrator] run_threat_classifier: "
        f"windows={len(preds_list)} suspicious={len(suspicious)}"
    )
    return {"threat_predictions": preds_list, "suspicious_windows": suspicious}


def summarize_incidents_node(state: OrchestratorState) -> OrchestratorState:
    print("[orchestrator] summarize_incidents: start")
    suspicious = state.get("suspicious_windows", [])
    if not suspicious:
        print("[orchestrator] summarize_incidents: no suspicious windows")
        return {"incident_summaries": []}
    events_df = _load_events_df(Path(state.get("events_df_path", "")))
    cfg = SummarizerConfig()
    summaries: List[Dict[str, object]] = []
    for item in suspicious:
        try:
            summary = summarize_incident_window(
                predicted_label=item["predicted_label"],
                proba=item.get("proba"),
                window_start=item["window_start"],
                window_end=item["window_end"],
                events_df=events_df,
                cfg=cfg,
                max_raw_lines=MAX_RAW_LINES,
            )
            summaries.append(
                {
                    "window_start": item["window_start"],
                    "window_end": item["window_end"],
                    "predicted_label": item["predicted_label"],
                    "proba": item.get("proba"),
                    "title": summary.title,
                    "description": summary.description,
                }
            )
        except Exception as exc:
            summaries.append(
                {
                    "window_start": item["window_start"],
                    "window_end": item["window_end"],
                    "predicted_label": item["predicted_label"],
                    "proba": item.get("proba"),
                    "error": str(exc),
                }
            )
    print(f"[orchestrator] summarize_incidents: summaries={len(summaries)}")
    return {"incident_summaries": summaries}


def _map_attack_type(label: str) -> str:
    mapping = {
        "bruteforce": "bruteforce",
        "port_scan": "port_scan",
        "ddos": "ddos",
        "api_enum": "api_enum",
    }
    return mapping.get(label.lower(), "unknown")


def _find_anomaly_score(state: OrchestratorState, window_start: str, window_end: str) -> Optional[float]:
    for item in state.get("anomaly_windows", []):
        if item.get("window_start") == window_start and item.get("window_end") == window_end:
            return float(item.get("anomaly_score"))
    return None


def _refine_payload_with_llm(payload: Dict[str, object]) -> Dict[str, object]:
    llm = ChatOpenAI(
        model=SummarizerConfig().model,
        base_url=SummarizerConfig().base_url,
        api_key=SummarizerConfig().api_key,
        temperature=0.0,
    )
    system = SystemMessage(
        content=(
            "You are a strict JSON formatter for incident payloads.\n"
            "Return ONLY JSON. Keep all required fields: first_seen_at, last_seen_at, title, "
            "attack_type, severity, status, source_ip, dest_ip, summary.\n"
            "Do not remove evidence or tags."
        )
    )
    human = HumanMessage(
        content=(
            "Normalize this incident payload to ensure required fields are present.\n"
            f"Payload JSON:\n{json.dumps(payload, ensure_ascii=False)}"
        )
    )
    resp = llm.invoke([system, human])
    cleaned = (resp.content or "").strip()
    return json.loads(cleaned)


def build_incident_payloads_node(state: OrchestratorState) -> OrchestratorState:
    print("[orchestrator] build_incident_payloads: start")
    summaries = state.get("incident_summaries", [])
    if not summaries:
        print("[orchestrator] build_incident_payloads: no summaries")
        return {"incident_payloads": []}
    events_df = _load_events_df(Path(state.get("events_df_path", "")))
    payloads: List[Dict[str, object]] = []

    for item in summaries:
        if "error" in item:
            continue
        window_start = item["window_start"]
        window_end = item["window_end"]
        predicted_label = str(item.get("predicted_label", "unknown"))
        proba = item.get("proba") or {}

        events_window = _filter_window(events_df, window_start, window_end)
        evidence = _extract_evidence(events_window, max_raw_lines=MAX_RAW_LINES)
        src_ip = _top_value(events_window.get("src_ip")) or _top_value(events_window.get("client_ip"))
        dst_ip = _top_value(events_window.get("dst_ip")) or ASSET_IP
        dpt = _top_value(events_window.get("dpt"))
        proto = _top_value(events_window.get("proto")) or "other"
        confidence = None
        if isinstance(proba, dict) and predicted_label in proba:
            confidence = int(float(proba[predicted_label]) * 100)
        anomaly_score = _find_anomaly_score(state, window_start, window_end)
        severity = _severity_from_inputs(confidence, anomaly_score)

        dest_port = None
        if dpt:
            try:
                dest_port = int(float(dpt))
            except (TypeError, ValueError):
                dest_port = None

        payload = {
            "first_seen_at": window_start,
            "last_seen_at": window_end,
            "title": (item.get("title") or f"Incident: {predicted_label}").strip(),
            "attack_type": _map_attack_type(predicted_label),
            "severity": severity,
            "confidence": confidence,
            "status": "open",
            "source_ip": src_ip or "0.0.0.0",
            "source_port": None,
            "dest_ip": dst_ip,
            "dest_port": dest_port,
            "protocol": proto,
            "asset": "",
            "tags": [predicted_label],
            "evidence": {
                "predicted_label": predicted_label,
                "proba": proba,
                "anomaly_score": anomaly_score,
                "evidence": evidence,
            },
            "summary": (item.get("description") or "").strip() or "Summary unavailable.",
            "action_taken": "",
            "external_refs": {},
        }

        if USE_LLM_REFINEMENT:
            try:
                payload = _refine_payload_with_llm(payload)
            except Exception:
                pass

        payloads.append(payload)

    print(f"[orchestrator] build_incident_payloads: payloads={len(payloads)}")
    return {"incident_payloads": payloads}


def create_incidents_node(state: OrchestratorState) -> OrchestratorState:
    print("[orchestrator] create_incidents: start")
    payloads = state.get("incident_payloads", [])
    if not payloads:
        print("[orchestrator] create_incidents: no payloads")
        return {"incident_create_results": []}

    dedupe = load_dedupe()
    results: List[Dict[str, object]] = []

    for payload in payloads:
        key = compute_incident_key(
            payload.get("first_seen_at"),
            payload.get("last_seen_at"),
            str(payload.get("attack_type", "")),
            str(payload.get("source_ip", "")),
        )
        if key in dedupe:
            results.append({"incident_key": key, "status": "skipped"})
            continue

        resp = create_incident(payload)
        results.append({"incident_key": key, "response": resp})
        if resp.get("status") == 201 and isinstance(resp.get("body"), dict):
            dedupe[key] = {
                "created_at": datetime.now(timezone.utc).isoformat(),
                "incident_id": resp["body"].get("id"),
            }

    save_dedupe(dedupe)
    print(f"[orchestrator] create_incidents: results={len(results)}")
    return {"incident_create_results": results}


def commit_offsets_node(state: OrchestratorState) -> OrchestratorState:
    print("[orchestrator] commit_offsets: start")
    offsets = state.get("next_offsets")
    if offsets is not None:
        save_offsets(offsets)
        print(f"[orchestrator] commit_offsets: files={len(offsets)}")
    return {"metrics": {"committed_at": datetime.now(timezone.utc).isoformat()}}
