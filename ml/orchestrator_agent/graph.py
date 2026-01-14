from __future__ import annotations

from pathlib import Path

try:
    from langgraph.checkpoint.sqlite import SqliteSaver
except Exception:  # pragma: no cover - optional dependency
    SqliteSaver = None  # type: ignore[assignment]
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph

from .config import STATE_DIR
from .nodes import (
    build_incident_payloads_node,
    commit_offsets_node,
    create_incidents_node,
    read_batch_node,
    run_anomaly_detector_node,
    run_etl_once_node,
    run_threat_classifier_node,
    summarize_incidents_node,
)
from .state import OrchestratorState


def build_graph() -> StateGraph:
    graph = StateGraph(OrchestratorState)

    graph.add_node("read_batch", read_batch_node)
    graph.add_node("run_etl_once", run_etl_once_node)
    graph.add_node("run_anomaly_detector", run_anomaly_detector_node)
    graph.add_node("run_threat_classifier", run_threat_classifier_node)
    graph.add_node("summarize_incidents", summarize_incidents_node)
    graph.add_node("build_incident_payloads", build_incident_payloads_node)
    graph.add_node("create_incidents", create_incidents_node)
    graph.add_node("commit_offsets", commit_offsets_node)

    graph.set_entry_point("read_batch")

    graph.add_conditional_edges(
        "read_batch",
        lambda state: "no_data" if state.get("no_new_data") else "has_data",
        {"no_data": END, "has_data": "run_etl_once"},
    )
    graph.add_edge("run_etl_once", "run_anomaly_detector")
    graph.add_conditional_edges(
        "run_anomaly_detector",
        lambda state: "no_anomaly" if not state.get("anomaly_any") else "has_anomaly",
        {"no_anomaly": "commit_offsets", "has_anomaly": "run_threat_classifier"},
    )
    graph.add_conditional_edges(
        "run_threat_classifier",
        lambda state: "no_threat" if not state.get("suspicious_windows") else "has_threat",
        {"no_threat": "commit_offsets", "has_threat": "summarize_incidents"},
    )
    graph.add_edge("summarize_incidents", "build_incident_payloads")
    graph.add_edge("build_incident_payloads", "create_incidents")
    graph.add_edge("create_incidents", "commit_offsets")
    graph.add_edge("commit_offsets", END)

    return graph


def build_compiled_graph():
    if SqliteSaver is not None:
        sqlite_path = Path(STATE_DIR) / "langgraph.sqlite"
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        checkpointer = SqliteSaver(str(sqlite_path))
    else:
        checkpointer = MemorySaver()
    return build_graph().compile(checkpointer=checkpointer)
