## Incident summarizer evaluation (LLM judge)

This folder evaluates the incident summarizer on **one sample window per scenario** from:
`ml/training_data/threat_classifier/test/`.

It runs the summarizer to produce a `(title, description)` per scenario, then uses a **different model**
as an LLM judge via **Deepeval GEval**. The judge is configured for **LM Studio**.

### Requirements

- **LM Studio** running an OpenAI-compatible server at `http://localhost:1234/v1`
- Judge model loaded in LM Studio: `qwen/qwen3-coder-30b`
- Python deps:

```bash
pip install -r ml/incident_summarizer/evaluate/requirements.txt
```

### Run

From the repo root:

```bash
export OPENAI_API_KEY="lm-studio"   # placeholder is fine for LM Studio
python -m ml.incident_summarizer.evaluate.run
```

This prints a compact report to stderr and writes JSONL results to:
`ml/incident_summarizer/evaluate/outputs/eval_results.jsonl`

To save somewhere else:

```bash
python -m ml.incident_summarizer.evaluate.run --out /tmp/eval_results.jsonl
```

To print JSONL to stdout instead:

```bash
python -m ml.incident_summarizer.evaluate.run --out -
```

### Notes

- The **summarizer model** defaults to `openai/gpt-oss-20b` (see `ml/incident_summarizer/summarizer.py`).
- The **judge model** defaults to `qwen/qwen3-coder-30b`.
- The script refuses to run if `--summarizer-model` equals `--judge-model` (to ensure judge != summarizer).

