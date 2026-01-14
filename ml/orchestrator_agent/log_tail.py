from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Tuple

from .state import OffsetsState


def _default_entry(path: Path) -> dict:
    return {"path": str(path), "pos_bytes": 0, "last_size": 0, "last_mtime": 0.0}


def _stat_file(path: Path) -> Tuple[int, float]:
    stat = path.stat()
    return stat.st_size, stat.st_mtime


def read_new_bytes(
    path: Path, entry: dict, max_bytes: int
) -> Tuple[bytes, dict, int]:
    if not path.exists():
        return b"", entry, 0

    size, mtime = _stat_file(path)
    pos = int(entry.get("pos_bytes", 0))

    if size < pos:
        pos = 0

    data = b""
    lines = 0
    if size > pos:
        with open(path, "rb") as handle:
            handle.seek(pos)
            data = handle.read(max_bytes)
        pos += len(data)
        lines = data.count(b"\n")

    return data, {
        "path": str(path),
        "pos_bytes": pos,
        "last_size": size,
        "last_mtime": mtime,
    }, lines


def read_batch(
    paths: Dict[str, Path],
    offsets: OffsetsState,
    target_lines: int,
    chunk_bytes: int,
) -> Tuple[Dict[str, bytes], OffsetsState, int, int]:
    data_by_file: Dict[str, bytes] = {key: b"" for key in paths}
    next_offsets: OffsetsState = {k: dict(v) for k, v in offsets.items()}
    total_bytes = 0
    total_lines = 0

    while total_lines < target_lines:
        progress = False
        for key, path in paths.items():
            entry = next_offsets.get(key, _default_entry(path))
            chunk, updated, lines = read_new_bytes(path, entry, chunk_bytes)
            if chunk:
                data_by_file[key] += chunk
                total_bytes += len(chunk)
                total_lines += lines
                progress = True
            next_offsets[key] = updated
            if total_lines >= target_lines:
                break
        if not progress:
            break

    return data_by_file, next_offsets, total_bytes, total_lines
