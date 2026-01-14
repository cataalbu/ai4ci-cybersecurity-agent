from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Dict

from .config import BACKEND_BASE_URL, BACKEND_TIMEOUT_SECONDS


def create_incident(payload: Dict[str, object]) -> Dict[str, object]:
    url = f"{BACKEND_BASE_URL.rstrip('/')}/api/incidents/"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=BACKEND_TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8")
            return {"status": resp.status, "body": json.loads(body) if body else {}}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8") if exc.fp else ""
        return {"status": exc.code, "error": body or str(exc)}
    except urllib.error.URLError as exc:
        return {"status": 0, "error": str(exc)}
