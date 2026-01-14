from __future__ import annotations

from ml.orchestrator_agent.utils import compute_incident_key


def test_incident_key_stable() -> None:
    key1 = compute_incident_key("2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "ddos", "1.2.3.4")
    key2 = compute_incident_key("2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "ddos", "1.2.3.4")
    assert key1 == key2


def test_incident_key_changes_on_fields() -> None:
    key1 = compute_incident_key("2026-01-01T00:00:00Z", "2026-01-01T00:01:00Z", "ddos", "1.2.3.4")
    key2 = compute_incident_key("2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z", "ddos", "1.2.3.4")
    assert key1 != key2
