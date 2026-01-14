#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pandas as pd

# Add project root to Python path (so `etl` and `ml.*` imports work when run as a script)
project_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(project_root))

from etl import run_etl  # noqa: E402
from ml.incident_summarizer import SummarizerConfig, summarize_incident_window  # noqa: E402
from ml.incident_summarizer.summarizer import _extract_evidence  # noqa: E402


SCENARIOS: Tuple[str, ...] = ("healthy", "bruteforce", "api_enum", "port_scan", "ddos")


def _read_manifest_first_per_scenario(manifest_path: Path, scenarios: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    needed = {s: None for s in scenarios}
    with manifest_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            scenario = str(obj.get("scenario", "")).strip()
            if scenario in needed and needed[scenario] is None:
                needed[scenario] = obj
            if all(v is not None for v in needed.values()):
                break

    missing = [k for k, v in needed.items() if v is None]
    if missing:
        raise ValueError(f"Manifest missing scenarios: {missing}")
    return {k: v for k, v in needed.items() if v is not None}


def _to_utc(ts: Any) -> pd.Timestamp:
    out = pd.to_datetime(ts, utc=True, errors="coerce")
    if pd.isna(out):
        raise ValueError(f"Invalid timestamp: {ts!r}")
    return out


def _slice_events(events_df: pd.DataFrame, window_start: Any, window_end: Any) -> pd.DataFrame:
    if "timestamp" not in events_df.columns:
        raise ValueError("events_df must contain a 'timestamp' column")
    ws = _to_utc(window_start)
    we = _to_utc(window_end)
    ts = pd.to_datetime(events_df["timestamp"], utc=True, errors="coerce")
    return events_df.loc[(ts >= ws) & (ts < we)].copy()


def _format_compact_report(rows: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for r in rows:
        scenario = r["scenario"]
        score = r.get("judge_score")
        score_str = "n/a" if score is None else f"{float(score):.3f}"
        lines.append(f"- {scenario:10s}  score={score_str}  title={r.get('title','')}")
        reason = (r.get("judge_reason") or "").strip()
        if reason:
            lines.append(f"  reason: {reason}")
    return "\n".join(lines)


def _build_deepeval_metric(
    *,
    judge_model_name: str,
    judge_base_url: str,
    judge_api_key: str,
):
    """
    Create a GEval metric using a *judge* model served via LM Studio.

    We prefer passing a model object explicitly (OpenAIModel). If the installed deepeval
    version doesn't support that for GEval, we fall back to env-based local-model config.
    """
    try:
        from deepeval.metrics import GEval  # type: ignore
        from deepeval.test_case import LLMTestCaseParams  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "deepeval is required for judging. Install it with: pip install deepeval"
        ) from exc

    # Configure keys the same way as summarizer.py: default to "lm-studio" if unset.
    # Deepeval 3.7.9 uses the OpenAI client internally, so we also set OPENAI_* vars
    # to point to LM Studio.
    os.environ.setdefault("OPENAI_API_KEY", judge_api_key or "lm-studio")
    os.environ.setdefault("OPENAI_BASE_URL", judge_base_url)

    # Keep these too (matches the Seminar4.ipynb pattern and Deepeval docs for local models)
    os.environ.setdefault("LOCAL_MODEL_API_KEY", judge_api_key or "lm-studio")
    os.environ.setdefault("LOCAL_MODEL_BASE_URL", judge_base_url)
    os.environ.setdefault("LOCAL_MODEL_MODEL_NAME", judge_model_name)

    criteria = (
        "You are a strict cybersecurity incident summary judge.\n"
        "You will receive:\n"
        "- INPUT: scenario label + time window\n"
        "- RETRIEVAL_CONTEXT: evidence extracted from logs (IPs, ports, paths, status codes, raw lines)\n"
        "- ACTUAL_OUTPUT: the incident summary (title + description)\n\n"
        "Score the summary from 0.0 to 1.0 using these rules:\n"
        "1) Scenario alignment: it matches the given scenario (healthy means no attack).\n"
        "2) Evidence grounding: concrete claims (IPs/ports/paths/timestamps/volumes) must be supported by context.\n"
        "3) Coverage: it must mention at least TWO concrete details present in the context "
        "(e.g., attacker IP, destination port, endpoint/path, time window, status codes, request volume).\n"
        "4) No hallucinations: penalize invented details.\n"
        "Return a brief reason that names the two concrete details you found (or explain what is missing)."
    )

    # Deepeval 3.7.9 doesn't expose OpenAIModel from deepeval.models; pass the model name
    # directly and rely on OPENAI_BASE_URL to route to LM Studio.
    return GEval(
        name="AttackSummaryQuality",
        criteria=criteria,
        evaluation_params=[
            LLMTestCaseParams.INPUT,
            LLMTestCaseParams.ACTUAL_OUTPUT,
            LLMTestCaseParams.RETRIEVAL_CONTEXT,
        ],
        threshold=0.0,
        model=judge_model_name,
    )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluate incident summarizer with an LLM judge (Deepeval).")
    ap.add_argument(
        "--dataset-dir",
        default=str(project_root / "ml" / "training_data" / "threat_classifier" / "test"),
        help="Directory containing nginx_access.log, api_app.log, fw_ufw.log and manifest.jsonl",
    )
    ap.add_argument(
        "--out",
        default=str(project_root / "ml" / "incident_summarizer" / "evaluate" / "outputs" / "eval_results.jsonl"),
        help='Output JSONL path (default: ml/incident_summarizer/evaluate/outputs/eval_results.jsonl). Use "-" for stdout.',
    )
    ap.add_argument("--max-raw-lines", type=int, default=10, help="Max raw log lines in evidence (default: 10)")

    # Summarizer model (must be different from judge model)
    ap.add_argument("--summarizer-model", default=SummarizerConfig().model)
    ap.add_argument("--summarizer-base-url", default=SummarizerConfig().base_url)
    ap.add_argument("--summarizer-temperature", type=float, default=SummarizerConfig().temperature)

    # Judge model (LM Studio Qwen)
    ap.add_argument("--judge-model", default="qwen/qwen3-coder-30b")
    ap.add_argument("--judge-base-url", default="http://localhost:1234/v1")
    ap.add_argument("--judge-temperature", type=float, default=0.0)
    args = ap.parse_args(argv)

    if str(args.summarizer_model).strip() == str(args.judge_model).strip():
        raise SystemExit(
            "Refusing to run: judge model must be different from summarizer model "
            f"(both are {args.judge_model!r}). Use --summarizer-model to change it."
        )

    dataset_dir = Path(args.dataset_dir)
    manifest_path = dataset_dir / "manifest.jsonl"
    nginx_path = dataset_dir / "nginx_access.log"
    api_path = dataset_dir / "api_app.log"
    ufw_path = dataset_dir / "fw_ufw.log"

    selected = _read_manifest_first_per_scenario(manifest_path, SCENARIOS)

    # ETL once for whole test log set
    etl_result = run_etl(
        nginx_path=str(nginx_path),
        api_path=str(api_path),
        ufw_path=str(ufw_path),
        skip_disk_write=True,
    )
    events_df = pd.DataFrame(etl_result.get("records", []))
    if events_df.empty:
        raise SystemExit("ETL produced no events; cannot evaluate.")

    summarizer_cfg = SummarizerConfig(
        model=str(args.summarizer_model),
        base_url=str(args.summarizer_base_url),
        api_key=os.getenv("OPENAI_API_KEY", "lm-studio"),
        temperature=float(args.summarizer_temperature),
    )

    judge_api_key = os.getenv("OPENAI_API_KEY", "lm-studio")
    metric = _build_deepeval_metric(
        judge_model_name=str(args.judge_model),
        judge_base_url=str(args.judge_base_url),
        judge_api_key=judge_api_key,
    )

    try:
        from deepeval.test_case import LLMTestCase  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "deepeval is required for judging. Install it with: pip install deepeval"
        ) from exc

    rows: List[Dict[str, Any]] = []
    for scenario in SCENARIOS:
        entry = selected[scenario]
        ws = entry["window_start"]
        we = entry["window_end"]

        # Generate summary for this scenario-window
        summary = summarize_incident_window(
            predicted_label=scenario,
            proba=None,
            window_start=ws,
            window_end=we,
            events_df=events_df,
            cfg=summarizer_cfg,
            max_raw_lines=int(args.max_raw_lines),
        )

        # Build judge evidence from the same window
        events_window = _slice_events(events_df, ws, we)
        evidence = _extract_evidence(events_window, max_raw_lines=int(args.max_raw_lines))

        test_case = LLMTestCase(
            input=json.dumps(
                {"scenario": scenario, "window": {"start": ws, "end": we}},
                ensure_ascii=False,
            ),
            actual_output=f"{summary.title}\n{summary.description}".strip(),
            retrieval_context=[json.dumps(evidence, ensure_ascii=False)],
        )

        # Run metric
        score = None
        reason = None
        try:
            metric.measure(test_case)  # typical deepeval API
            score = getattr(metric, "score", None)
            reason = getattr(metric, "reason", None)
        except Exception as exc:
            reason = f"judge_failed: {exc}"

        row = {
            "scenario": scenario,
            "window_start": ws,
            "window_end": we,
            "summarizer_model": summarizer_cfg.model,
            "judge_model": str(args.judge_model),
            "title": summary.title,
            "description": summary.description,
            "judge_score": score,
            "judge_reason": reason,
        }
        rows.append(row)

    if args.out == "-":
        out_fh = sys.stdout
        out_path: Optional[Path] = None
    else:
        out_path = Path(str(args.out))
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_fh = open(out_path, "w", encoding="utf-8")
    try:
        for r in rows:
            out_fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    finally:
        if out_fh is not sys.stdout:
            out_fh.close()

    print("\n" + _format_compact_report(rows), file=sys.stderr)
    if out_path is not None:
        print(f"\nSaved JSONL results to: {out_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

