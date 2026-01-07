from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from ..schemas import SOURCE_UFW, NormalizedRecord, base_record

# Example:
# Jan 07 08:52:06 web-1 kernel: [UFW ALLOW] IN=eth0 OUT= MAC=... SRC=49.202.24.19 DST=203.0.113.20 LEN=60 ... PROTO=TCP SPT=54321 DPT=80 ...
LOG_PATTERN = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<hostname>\S+)\s+\S+:\s+\[UFW\s+(?P<verdict>ALLOW|BLOCK|DENY|REJECT)\]\s+'
    r'.*?\bSRC=(?P<src_ip>\S+)\s+DST=(?P<dst_ip>\S+)'
    r'.*?\bPROTO=(?P<proto>\w+)\s+SPT=(?P<spt>\d+)\s+DPT=(?P<dpt>\d+)'
)


def _build_timestamp(month: str, day: str, time_str: str) -> datetime:
    """Construct timezone-aware timestamp; inject current year and adjust to UTC."""
    now = datetime.now().astimezone()
    candidate = datetime.strptime(
        f"{now.year} {month} {int(day):02d} {time_str}", "%Y %b %d %H:%M:%S"
    ).replace(tzinfo=now.tzinfo)

    # Handle year rollover (e.g., January parsing December logs)
    if candidate - now > timedelta(days=1):
        candidate = candidate.replace(year=now.year - 1)

    return candidate.astimezone(timezone.utc)


def parse_line(line: str) -> NormalizedRecord:
    """Parse a single UFW firewall log line."""
    raw_line = line.rstrip("\n")
    record = base_record(SOURCE_UFW, raw_line)
    match = LOG_PATTERN.match(raw_line.strip())
    if not match:
        record["parse_ok"] = False
        record["parse_error"] = "failed to match ufw log pattern"
        return record

    try:
        record["timestamp"] = _build_timestamp(
            match.group("month"), match.group("day"), match.group("time")
        )
        record["hostname"] = match.group("hostname")
        record["verdict"] = match.group("verdict")
        record["src_ip"] = match.group("src_ip")
        record["dst_ip"] = match.group("dst_ip")
        record["proto"] = match.group("proto")
        record["spt"] = int(match.group("spt"))
        record["dpt"] = int(match.group("dpt"))
    except Exception as exc:  # pragma: no cover - defensive
        record["parse_ok"] = False
        record["parse_error"] = f"exception during parse: {exc}"

    return record

