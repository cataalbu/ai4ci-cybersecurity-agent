from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Sequence, Tuple

from .schemas import NormalizedRecord

ParserFunc = Callable[[str], NormalizedRecord]


@dataclass
class FileSummary:
    file: str
    total: int
    ok: int
    failed: int


def process_file(path: str, parser: ParserFunc) -> Tuple[List[NormalizedRecord], FileSummary]:
    """Parse a single file and return records with a summary."""
    records: List[NormalizedRecord] = []
    total = ok = failed = 0

    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            total += 1
            record = parser(line)
            if record.get("parse_ok"):
                ok += 1
            else:
                failed += 1
            records.append(record)

    return records, FileSummary(path, total, ok, failed)


def flatten(all_records: Sequence[Sequence[NormalizedRecord]]) -> List[NormalizedRecord]:
    """Flatten a list of record iterables into a single list."""
    merged: List[NormalizedRecord] = []
    for chunk in all_records:
        merged.extend(chunk)
    return merged

