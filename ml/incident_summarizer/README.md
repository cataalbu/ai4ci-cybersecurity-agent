# Incident Summarizer (LLM)

This module generates a human-readable **incident title** and **incident description** after the threat classifier has produced per-window predictions.

It reuses the same LangChain/OpenAI client defaults as `data-generation/llm_log_traffic_langchain.py`:

- **model**: `openai/gpt-oss-20b`
- **base_url**: `http://localhost:1234/v1`
- **api_key**: from `OPENAI_API_KEY` (fallback `lm-studio`)
- **temperature**: `0.2`

## How it works

- The threat classifier predicts a label per time window (`window_start`, `window_end`).
- ETL normalizes logs into events that contain useful evidence like `client_ip`, `src_ip`, `dpt`, `path`, `status`, and `raw_line`.
- The summarizer extracts compact evidence for the window and asks the LLM for JSON:
  - `title`
  - `description` (includes attacker / attack details like IPs/ports/paths/status codes)

## Run (post-classifier)

Use the runner script:

```bash
python ml/threat_classifier/summarize_incidents.py \
  --log-dir ./path/to/logs_dir \
  --window-seconds 60 \
  --model-dir ./models/xgb-threat \
  --out ./incidents.jsonl \
  --min-proba 0.0
```

Expected `--log-dir` contents:

- `nginx_access.log`
- `api_app.log`
- `fw_ufw.log`

Output is **JSONL**, one record per included window:

- `window_start`, `window_end`
- `predicted_label`, `proba`
- `title`, `description`

Notes:

- By default, windows predicted as `healthy` are **excluded**. Use `--include-healthy` to include them.
- The script calls the LLM once per included window.

