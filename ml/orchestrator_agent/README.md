# Orchestrator Agent (LangGraph)

Runs a continuous orchestration loop that tails `logs/`, runs anomaly detection and threat classification, optionally summarizes incidents with GPT‑OSS, and creates incidents in the backend API.

## Quick start

```bash
python -m ml.orchestrator_agent.run --once
```

```bash
python -m ml.orchestrator_agent.run --loop
```

## Environment

- `ORCH_LOG_DIR` (default: `logs`)
- `ORCH_BATCH_TARGET_LINES` (default: `50`)
- `ORCH_READ_CHUNK_BYTES` (default: `64000`)
- `ORCH_POLL_INTERVAL_SECONDS` (default: `1.0`)
- `ORCH_WINDOW_SECONDS` (default: `60`)
- `ORCH_ANOMALY_MODEL_DIR` (default: `models/iforest`)
- `ORCH_THREAT_MODEL_DIR` (default: `models/xgb-threat`)
- `ORCH_BACKEND_BASE_URL` (default: `http://localhost:8000`)
- `ORCHESTRATOR_ASSET_IP` (default: `127.0.0.1`)
- `ORCH_USE_LLM_REFINEMENT` (default: `false`)
- `OPENAI_API_KEY` (required by GPT‑OSS endpoint)
- `OPENAI_BASE_URL` (if using a non-default GPT‑OSS endpoint)

## Notes

- The agent expects `logs/nginx_access.log`, `logs/api_app.log`, and `logs/fw_ufw.log`.
- LLM summaries use GPT‑OSS via `ml.incident_summarizer` defaults (LM Studio compatible).
