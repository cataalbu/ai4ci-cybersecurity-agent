from __future__ import annotations

from pathlib import Path

from ml.orchestrator_agent.log_tail import read_batch


def test_read_batch_reads_new_bytes(tmp_path: Path) -> None:
    log_path = tmp_path / "nginx_access.log"
    log_path.write_bytes(b"first\n")

    data, offsets, total = read_batch({"nginx": log_path}, {}, 10, 1024)
    assert total == len(b"first\n")
    assert data["nginx"] == b"first\n"

    with open(log_path, "ab") as handle:
        handle.write(b"second\n")

    data2, offsets2, total2 = read_batch({"nginx": log_path}, offsets, 10, 1024)
    assert total2 == len(b"second\n")
    assert data2["nginx"] == b"second\n"
    assert offsets2["nginx"]["pos_bytes"] > offsets["nginx"]["pos_bytes"]


def test_read_batch_resets_on_truncation(tmp_path: Path) -> None:
    log_path = tmp_path / "api_app.log"
    log_path.write_bytes(b"abcdef\n")

    data, offsets, total = read_batch({"api": log_path}, {}, 10, 1024)
    assert total == len(b"abcdef\n")
    assert data["api"] == b"abcdef\n"

    log_path.write_bytes(b"short\n")
    data2, offsets2, total2 = read_batch({"api": log_path}, offsets, 10, 1024)
    assert total2 == len(b"short\n")
    assert data2["api"] == b"short\n"
    assert offsets2["api"]["pos_bytes"] == len(b"short\n")
