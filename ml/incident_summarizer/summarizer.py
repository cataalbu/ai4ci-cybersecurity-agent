from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI


@dataclass(frozen=True)
class SummarizerConfig:
    """
    LLM configuration reused from data-generation/llm_log_traffic_langchain.py.

    Defaults intentionally match:
      - model: "openai/gpt-oss-20b"
      - base_url: "http://localhost:1234/v1"
      - api_key: env OPENAI_API_KEY (fallback "lm-studio")
      - temperature: 0.2
    """

    model: str = "openai/gpt-oss-20b"
    base_url: str = "http://localhost:1234/v1"
    api_key: str = os.getenv("OPENAI_API_KEY", "lm-studio")
    temperature: float = 0.2


@dataclass(frozen=True)
class IncidentSummary:
    title: str
    description: str


def _to_utc(ts: Any) -> pd.Timestamp:
    out = pd.to_datetime(ts, utc=True, errors="coerce")
    if pd.isna(out):
        raise ValueError(f"Invalid timestamp: {ts!r}")
    return out


def _top_counts(series: pd.Series, k: int = 5) -> List[Tuple[str, int]]:
    if series is None or series.empty:
        return []
    counts = series.dropna().astype(str).value_counts()
    return [(str(idx), int(val)) for idx, val in counts.head(k).items()]


def _maybe_int(x: Any) -> Optional[int]:
    try:
        if x is None or (isinstance(x, float) and pd.isna(x)):
            return None
        return int(x)
    except Exception:
        return None


def _extract_evidence(events_window: pd.DataFrame, max_raw_lines: int = 10) -> Dict[str, Any]:
    """
    Extract compact, model-friendly evidence from normalized ETL events for one window.
    """
    if events_window.empty:
        return {
            "counts": {"total": 0, "nginx": 0, "api": 0, "ufw": 0},
            "top_client_ips": [],
            "top_ufw_src_ips": [],
            "top_ufw_block_dpt": [],
            "top_paths": [],
            "status_counts": {},
            "raw_lines_sample": [],
        }

    df = events_window.copy()
    src = df.get("source")
    counts = {
        "total": int(len(df)),
        "nginx": int((src == "nginx").sum()) if src is not None else 0,
        "api": int((src == "api").sum()) if src is not None else 0,
        "ufw": int((src == "ufw").sum()) if src is not None else 0,
    }

    # IPs (nginx/api client_ip, ufw src_ip)
    client_ips = pd.concat(
        [
            df.loc[df.get("source") == "nginx", "client_ip"] if "client_ip" in df else pd.Series([], dtype=object),
            df.loc[df.get("source") == "api", "client_ip"] if "client_ip" in df else pd.Series([], dtype=object),
        ],
        ignore_index=True,
    )
    top_client_ips = _top_counts(client_ips, k=5)
    top_ufw_src_ips = _top_counts(df["src_ip"] if "src_ip" in df else pd.Series([], dtype=object), k=5)

    # Ports (focus on blocked destinations if available)
    ufw_df = df[df.get("source") == "ufw"] if "source" in df else df.iloc[0:0]
    if not ufw_df.empty and "verdict" in ufw_df.columns:
        ufw_block = ufw_df[ufw_df["verdict"].astype(str).str.upper().eq("BLOCK")]
    else:
        ufw_block = ufw_df
    top_ufw_block_dpt = _top_counts(ufw_block["dpt"] if "dpt" in ufw_block else pd.Series([], dtype=object), k=8)

    # Paths (nginx+api)
    path_series = pd.concat(
        [
            df.loc[df.get("source") == "nginx", "path"] if "path" in df else pd.Series([], dtype=object),
            df.loc[df.get("source") == "api", "path"] if "path" in df else pd.Series([], dtype=object),
        ],
        ignore_index=True,
    )
    top_paths = _top_counts(path_series, k=8)

    # Status counts (nginx+api)
    status_series = pd.concat(
        [
            df.loc[df.get("source") == "nginx", "status"] if "status" in df else pd.Series([], dtype=object),
            df.loc[df.get("source") == "api", "status"] if "status" in df else pd.Series([], dtype=object),
        ],
        ignore_index=True,
    )
    status_numeric = pd.to_numeric(status_series, errors="coerce").dropna().astype(int)
    status_counts = {str(k): int(v) for k, v in status_numeric.value_counts().head(10).items()}

    # Small raw line sample (most useful for LLM grounding)
    raw_lines = []
    if "raw_line" in df.columns:
        # Prefer ufw BLOCK lines, then api WARN/ERROR, then nginx 4xx/5xx
        raw_ufw = []
        if not ufw_df.empty and "raw_line" in ufw_df.columns:
            if "verdict" in ufw_df.columns:
                raw_ufw = ufw_df.loc[
                    ufw_df["verdict"].astype(str).str.upper().eq("BLOCK"), "raw_line"
                ].dropna().astype(str).tolist()
            else:
                raw_ufw = ufw_df["raw_line"].dropna().astype(str).tolist()

        api_df = df[df.get("source") == "api"] if "source" in df else df.iloc[0:0]
        raw_api = []
        if not api_df.empty and "raw_line" in api_df.columns:
            if "level" in api_df.columns:
                raw_api = api_df.loc[
                    api_df["level"].astype(str).str.upper().isin(["WARN", "ERROR"]), "raw_line"
                ].dropna().astype(str).tolist()
            else:
                raw_api = api_df["raw_line"].dropna().astype(str).tolist()

        nginx_df = df[df.get("source") == "nginx"] if "source" in df else df.iloc[0:0]
        raw_nginx = []
        if not nginx_df.empty and "raw_line" in nginx_df.columns:
            if "status" in nginx_df.columns:
                st = pd.to_numeric(nginx_df["status"], errors="coerce")
                raw_nginx = nginx_df.loc[(st >= 400) & (st < 600), "raw_line"].dropna().astype(str).tolist()
            else:
                raw_nginx = nginx_df["raw_line"].dropna().astype(str).tolist()

        raw_lines = (raw_ufw + raw_api + raw_nginx)[:max_raw_lines]

    return {
        "counts": counts,
        "top_client_ips": top_client_ips,
        "top_ufw_src_ips": top_ufw_src_ips,
        "top_ufw_block_dpt": top_ufw_block_dpt,
        "top_paths": top_paths,
        "status_counts": status_counts,
        "raw_lines_sample": raw_lines,
    }


_JSON_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE | re.MULTILINE)


def _parse_summary_json(text: str) -> IncidentSummary:
    cleaned = (text or "").strip()
    cleaned = _JSON_FENCE_RE.sub("", cleaned).strip()
    try:
        obj = json.loads(cleaned)
    except Exception:
        # Last-resort: attempt to locate first JSON object
        m = re.search(r"\{[\s\S]*\}", cleaned)
        if not m:
            raise ValueError(f"LLM response is not valid JSON: {cleaned[:200]!r}")
        obj = json.loads(m.group(0))

    title = str(obj.get("title", "")).strip()
    description = str(obj.get("description", "")).strip()
    if not title or not description:
        raise ValueError(f"Missing title/description in LLM JSON: keys={list(obj.keys())}")
    return IncidentSummary(title=title, description=description)


def summarize_incident_window(
    *,
    predicted_label: str,
    proba: Optional[Dict[str, float]],
    window_start: Any,
    window_end: Any,
    events_df: pd.DataFrame,
    cfg: SummarizerConfig = SummarizerConfig(),
    max_raw_lines: int = 10,
) -> IncidentSummary:
    """
    Summarize a single classified time window into an incident title/description.

    The caller is expected to provide:
      - classifier output (predicted_label + proba dict)
      - window_start/window_end matching the feature windows
      - events_df: normalized ETL events for the whole log set (will be filtered to the window)
    """
    ws = _to_utc(window_start)
    we = _to_utc(window_end)

    if "timestamp" not in events_df.columns:
        raise ValueError("events_df must contain a 'timestamp' column")

    ts = pd.to_datetime(events_df["timestamp"], utc=True, errors="coerce")
    events_window = events_df.loc[(ts >= ws) & (ts < we)].copy()

    evidence = _extract_evidence(events_window, max_raw_lines=max_raw_lines)
    top3 = []
    if proba:
        try:
            top3 = sorted(proba.items(), key=lambda kv: float(kv[1]), reverse=True)[:3]
        except Exception:
            top3 = list(proba.items())[:3]

    llm = ChatOpenAI(
        model=cfg.model,
        base_url=cfg.base_url,
        api_key=cfg.api_key,
        temperature=cfg.temperature,
    )

    system = SystemMessage(
        content=(
            "You are a cybersecurity incident summarizer.\n"
            "Return ONLY strict JSON with keys: title, description.\n"
            "Description must include concrete evidence such as IPs, ports, paths, status codes when available.\n"
            "Do not include code fences, markdown, or extra keys."
        )
    )

    prompt_obj = {
        "window": {"start": ws.isoformat(), "end": we.isoformat()},
        "classifier": {"predicted_label": predicted_label, "top3_proba": top3},
        "evidence": evidence,
        "requirements": {
            "title": "Short, specific (<= 12 words).",
            "description": (
                "2-6 sentences. Mention attacker/attack details (IPs/ports/paths). "
                "Be explicit about what was observed in logs."
            ),
        },
    }

    human = HumanMessage(
        content=(
            "Summarize this potential security incident.\n\n"
            "Input JSON:\n"
            f"{json.dumps(prompt_obj, ensure_ascii=False)}"
        )
    )

    msg = llm.invoke([system, human])
    return _parse_summary_json((msg.content or "").strip())

