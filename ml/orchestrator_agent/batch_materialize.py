from __future__ import annotations

from pathlib import Path
from typing import Dict

from .config import LOG_FILES


def materialize_batch(batch_dir: Path, data_by_file: Dict[str, bytes]) -> None:
    batch_dir.mkdir(parents=True, exist_ok=True)
    for key, filename in LOG_FILES.items():
        payload = data_by_file.get(key, b"")
        path = batch_dir / filename
        with open(path, "wb") as handle:
            handle.write(payload)
