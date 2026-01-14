from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]

LOG_DIR = Path(os.getenv("ORCH_LOG_DIR", PROJECT_ROOT / "logs"))
STATE_DIR = Path(os.getenv("ORCH_STATE_DIR", Path(__file__).resolve().parent / ".state"))
BATCHES_DIR = STATE_DIR / "batches"

BATCH_TARGET_LINES = int(os.getenv("ORCH_BATCH_TARGET_LINES", "50"))
READ_CHUNK_BYTES = int(os.getenv("ORCH_READ_CHUNK_BYTES", "64000"))
POLL_INTERVAL_SECONDS = float(os.getenv("ORCH_POLL_INTERVAL_SECONDS", "1.0"))
WINDOW_SECONDS = int(os.getenv("ORCH_WINDOW_SECONDS", "60"))

ANOMALY_MODEL_DIR = Path(
    os.getenv("ORCH_ANOMALY_MODEL_DIR", PROJECT_ROOT / "models" / "iforest")
)
THREAT_MODEL_DIR = Path(
    os.getenv("ORCH_THREAT_MODEL_DIR", PROJECT_ROOT / "models" / "xgb-threat")
)

BACKEND_BASE_URL = os.getenv("ORCH_BACKEND_BASE_URL", "http://localhost:8000")
BACKEND_TIMEOUT_SECONDS = float(os.getenv("ORCH_BACKEND_TIMEOUT_SECONDS", "10"))

ASSET_IP = os.getenv("ORCHESTRATOR_ASSET_IP", "127.0.0.1")
USE_LLM_REFINEMENT = os.getenv("ORCH_USE_LLM_REFINEMENT", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
MAX_RAW_LINES = int(os.getenv("ORCH_MAX_RAW_LINES", "10"))

LOG_FILES = {
    "nginx": "nginx_access.log",
    "api": "api_app.log",
    "ufw": "fw_ufw.log",
}
