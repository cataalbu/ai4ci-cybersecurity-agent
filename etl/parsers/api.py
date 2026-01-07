from __future__ import annotations

import re
from datetime import datetime, timezone

from ..schemas import SOURCE_API, NormalizedRecord, base_record

# Example:
# 2026-01-07T09:26:51.011Z level=INFO ip=203.0.113.9 method=GET path=/api/v1/items status=200 latency_ms=123 user=alice msg="ok"
LOG_PATTERN = re.compile(
    r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+'
    r'level=(?P<level>[A-Z]+)\s+'
    r'ip=(?P<ip>\S+)\s+'
    r'method=(?P<method>[A-Z]+)\s+'
    r'path=(?P<path>\S+)\s+'
    r'status=(?P<status>\d+)\s+'
    r'latency_ms=(?P<latency_ms>\d+)\s+'
    r'user=(?P<user>\S+)\s+'
    r'msg="(?P<msg>.*)"$'
)


def parse_line(line: str) -> NormalizedRecord:
    """Parse a single API application log line."""
    raw_line = line.rstrip("\n")
    record = base_record(SOURCE_API, raw_line)
    match = LOG_PATTERN.match(raw_line.strip())
    if not match:
        record["parse_ok"] = False
        record["parse_error"] = "failed to match api log pattern"
        return record

    try:
        ts = match.group("timestamp").replace("Z", "+00:00")
        record["timestamp"] = datetime.fromisoformat(ts).astimezone(timezone.utc)
        record["client_ip"] = match.group("ip")
        record["method"] = match.group("method")
        record["path"] = match.group("path")
        record["status"] = int(match.group("status"))
        record["level"] = match.group("level")
        record["latency_ms"] = int(match.group("latency_ms"))
        record["user"] = None if match.group("user") in ("-", "null") else match.group("user")
        record["msg"] = match.group("msg")
    except Exception as exc:  # pragma: no cover - defensive
        record["parse_ok"] = False
        record["parse_error"] = f"exception during parse: {exc}"

    return record

