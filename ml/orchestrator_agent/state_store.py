from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict

from .config import STATE_DIR
from .state import OffsetsState


OFFSETS_PATH = STATE_DIR / "log_offsets.json"
DEDUPE_PATH = STATE_DIR / "incident_dedupe.json"


def _atomic_write(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    os.replace(tmp_path, path)


def load_offsets() -> OffsetsState:
    if not OFFSETS_PATH.exists():
        return {}
    with open(OFFSETS_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


def save_offsets(offsets: OffsetsState) -> None:
    _atomic_write(OFFSETS_PATH, offsets)


def load_dedupe() -> Dict[str, Dict[str, object]]:
    if not DEDUPE_PATH.exists():
        return {}
    with open(DEDUPE_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


def save_dedupe(dedupe: Dict[str, Dict[str, object]]) -> None:
    _atomic_write(DEDUPE_PATH, dedupe)
