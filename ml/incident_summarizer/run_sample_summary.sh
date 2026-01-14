#!/usr/bin/env bash
set -euo pipefail

# Simple wrapper to run the incident summarizer against the bundled sample logs.
# Requires the threat classifier model at ./models/xgb-threat and the LLM endpoint
# configured via OPENAI_API_KEY (defaults to "lm-studio" if unset).

LOG_DIR="ml/training_data/threat_classifier/sample_bruteforce"
WINDOW_SECONDS=60
MODEL_DIR="models/xgb-threat"

python ml/incident_summarizer/summarize_incidents.py \
  --log-dir "${LOG_DIR}" \
  --window-seconds "${WINDOW_SECONDS}" \
  --model-dir "${MODEL_DIR}" \
  --out - \
  --include-healthy

