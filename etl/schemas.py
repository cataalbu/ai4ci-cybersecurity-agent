from __future__ import annotations

from datetime import datetime
from typing import List, Optional, TypedDict

# Standardized sources
SOURCE_NGINX = "nginx"
SOURCE_API = "api"
SOURCE_UFW = "ufw"

# Stable column order for output
SCHEMA_FIELDS: List[str] = [
    "timestamp",
    "source",
    "client_ip",
    "method",
    "path",
    "status",
    "bytes_sent",
    "referer",
    "user_agent",
    "level",
    "latency_ms",
    "user",
    "msg",
    "hostname",
    "verdict",
    "src_ip",
    "dst_ip",
    "proto",
    "spt",
    "dpt",
    "raw_line",
    "parse_ok",
    "parse_error",
]


class NormalizedRecord(TypedDict, total=False):
    timestamp: Optional[datetime]
    source: str
    client_ip: Optional[str]
    method: Optional[str]
    path: Optional[str]
    status: Optional[int]
    bytes_sent: Optional[int]
    referer: Optional[str]
    user_agent: Optional[str]
    level: Optional[str]
    latency_ms: Optional[int]
    user: Optional[str]
    msg: Optional[str]
    hostname: Optional[str]
    verdict: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    proto: Optional[str]
    spt: Optional[int]
    dpt: Optional[int]
    raw_line: str
    parse_ok: bool
    parse_error: str


def base_record(source: str, raw_line: str) -> NormalizedRecord:
    """Create a new record pre-populated with required fields."""
    record: NormalizedRecord = {
        "timestamp": None,
        "source": source,
        "client_ip": None,
        "method": None,
        "path": None,
        "status": None,
        "bytes_sent": None,
        "referer": None,
        "user_agent": None,
        "level": None,
        "latency_ms": None,
        "user": None,
        "msg": None,
        "hostname": None,
        "verdict": None,
        "src_ip": None,
        "dst_ip": None,
        "proto": None,
        "spt": None,
        "dpt": None,
        "raw_line": raw_line,
        "parse_ok": True,
        "parse_error": "",
    }
    return record

