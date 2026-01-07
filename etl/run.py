from __future__ import annotations

import sys
from typing import List, Tuple

from .io import write_output
from .normalize import FileSummary, flatten, process_file
from .parsers import api as api_parser
from .parsers import nginx as nginx_parser
from .parsers import ufw as ufw_parser
from .schemas import NormalizedRecord


def _handle_file(path: str, parser, label: str) -> Tuple[List[NormalizedRecord], FileSummary]:
    try:
        return process_file(path, parser)
    except FileNotFoundError:
        print(f"[warn] {label} file not found: {path}", file=sys.stderr)
    except Exception as exc:
        print(f"[error] failed to process {label} file {path}: {exc}", file=sys.stderr)
    return [], FileSummary(path, 0, 0, 0)


def run_etl(
    nginx_path: str | None = None,
    api_path: str | None = None,
    ufw_path: str | None = None,
    out_path: str = "./data/events.parquet",
) -> dict:
    """
    Parse provided log files, normalize records, and write output.

    Returns a dict with keys:
      - records: list of NormalizedRecord
      - summaries: list of FileSummary
      - output_path: final output path (parquet or csv)
      - total_rows: number of emitted rows
    """
    all_record_chunks: List[List[NormalizedRecord]] = []
    summaries: List[FileSummary] = []

    if nginx_path:
        records, summary = _handle_file(nginx_path, nginx_parser.parse_line, "nginx")
        all_record_chunks.append(records)
        summaries.append(summary)
    if api_path:
        records, summary = _handle_file(api_path, api_parser.parse_line, "api")
        all_record_chunks.append(records)
        summaries.append(summary)
    if ufw_path:
        records, summary = _handle_file(ufw_path, ufw_parser.parse_line, "ufw")
        all_record_chunks.append(records)
        summaries.append(summary)

    records = flatten(all_record_chunks)
    output_path = write_output(records, out_path)

    return {
        "records": records,
        "summaries": summaries,
        "output_path": output_path,
        "total_rows": len(records),
    }

