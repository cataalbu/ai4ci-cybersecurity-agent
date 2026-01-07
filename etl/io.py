from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from typing import Iterable, List

from .schemas import NormalizedRecord, SCHEMA_FIELDS


def _safe_value(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    return value


def write_output(records: Iterable[NormalizedRecord], out_path: str) -> str:
    """Write records to parquet when possible, else CSV. Returns final path."""
    records_list: List[NormalizedRecord] = list(records)
    output_dir = os.path.dirname(out_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    final_path = out_path

    try:
        import pandas as pd  # type: ignore

        df = pd.DataFrame(records_list)
        df = df.reindex(columns=SCHEMA_FIELDS)
        try:
            df.to_parquet(out_path, index=False)
            return final_path
        except Exception:
            # Fall back to CSV if parquet backend not available
            final_path = (
                out_path[:-8] + ".csv" if out_path.lower().endswith(".parquet") else out_path
            )
            df.to_csv(final_path, index=False)
            return final_path
    except Exception:
        # Pandas not available; manual CSV
        final_path = out_path
        if out_path.lower().endswith(".parquet"):
            final_path = out_path[:-8] + ".csv"

        with open(final_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=SCHEMA_FIELDS)
            writer.writeheader()
            for record in records_list:
                row = {field: _safe_value(record.get(field)) for field in SCHEMA_FIELDS}
                writer.writerow(row)

        return final_path

