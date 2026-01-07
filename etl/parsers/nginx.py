from __future__ import annotations

import re
from datetime import datetime, timezone

from ..schemas import SOURCE_NGINX, NormalizedRecord, base_record

# Regex for Nginx combined log format
LOG_PATTERN = re.compile(
    r'^(?P<client_ip>[\d.:a-fA-F]+)\s+\S+\s+\S+\s+\['
    r'(?P<timestamp>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+'
    r'(?P<path>[^ ]+)\s+HTTP/(?P<http_version>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes_sent>\d+|-)'
    r'\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)


def parse_line(line: str) -> NormalizedRecord:
    """Parse a single Nginx combined access log line."""
    raw_line = line.rstrip("\n")
    record = base_record(SOURCE_NGINX, raw_line)
    match = LOG_PATTERN.match(raw_line.strip())
    if not match:
        record["parse_ok"] = False
        record["parse_error"] = "failed to match nginx log pattern"
        return record

    try:
        ts_str = match.group("timestamp")
        record["timestamp"] = datetime.strptime(
            ts_str, "%d/%b/%Y:%H:%M:%S %z"
        ).astimezone(timezone.utc)

        record["client_ip"] = match.group("client_ip")
        record["method"] = match.group("method")
        record["path"] = match.group("path")
        record["status"] = int(match.group("status"))
        bytes_sent = match.group("bytes_sent")
        record["bytes_sent"] = int(bytes_sent) if bytes_sent != "-" else None
        record["referer"] = match.group("referer") or None
        record["user_agent"] = match.group("user_agent") or None
    except Exception as exc:  # pragma: no cover - defensive
        record["parse_ok"] = False
        record["parse_error"] = f"exception during parse: {exc}"

    return record

