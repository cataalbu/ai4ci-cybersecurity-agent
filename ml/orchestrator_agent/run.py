from __future__ import annotations

import argparse
import time
from typing import Dict

from .config import POLL_INTERVAL_SECONDS
from .graph import build_compiled_graph
from .state_store import load_offsets


def _initial_state() -> Dict[str, object]:
    return {"next_offsets": load_offsets()}


def run_once() -> Dict[str, object]:
    graph = build_compiled_graph()
    return graph.invoke(_initial_state(), {"configurable": {"thread_id": "orchestrator"}})


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the LangGraph orchestration agent.")
    ap.add_argument("--once", action="store_true", help="Run a single cycle and exit.")
    ap.add_argument("--loop", action="store_true", help="Run continuously with polling.")
    args = ap.parse_args()

    if args.once:
        run_once()
        return 0
    if args.loop:
        while True:
            result = run_once()
            if result.get("no_new_data"):
                time.sleep(POLL_INTERVAL_SECONDS)
        return 0

    ap.error("Specify --once or --loop.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
