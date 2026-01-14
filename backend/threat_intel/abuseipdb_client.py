import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

try:
    import httpx
except Exception:  # pragma: no cover - optional dependency
    httpx = None

try:
    import requests
except Exception:  # pragma: no cover - optional dependency
    requests = None


class AbuseIpDbError(Exception):
    pass


class AbuseIpDbUnavailable(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class AbuseIpDbClient:
    api_key: str | None
    base_url: str
    timeout_seconds: int
    retries: int

    def check_ip(self, ip: str, max_age_days: int, verbose: bool) -> dict:
        if not self.api_key:
            raise AbuseIpDbUnavailable("missing_api_key")

        url = f"{self.base_url.rstrip('/')}/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": int(max_age_days),
            "verbose": "true" if verbose else "false",
        }
        headers = {
            "Accept": "application/json",
            "Key": self.api_key,
        }

        for attempt in range(self.retries + 1):
            try:
                status, resp_headers, body = self._do_request(url, params, headers)
            except Exception as exc:
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    continue
                raise AbuseIpDbError("network_error") from exc

            if status in (401, 403):
                raise AbuseIpDbUnavailable("auth_failed")
            if status == 429:
                if attempt < self.retries:
                    retry_after = self._parse_retry_after(resp_headers.get("Retry-After"))
                    self._sleep_backoff(attempt, retry_after)
                    continue
                raise AbuseIpDbUnavailable("rate_limited")
            if 400 <= status < 500:
                raise AbuseIpDbError(f"client_error:{status}")
            if status >= 500:
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    continue
                raise AbuseIpDbError(f"server_error:{status}")

            try:
                return json.loads(body)
            except ValueError as exc:
                raise AbuseIpDbError("invalid_json") from exc

        raise AbuseIpDbError("unexpected_retry_exhaustion")

    def _do_request(self, url: str, params: dict, headers: dict) -> tuple[int, dict, str]:
        if httpx is not None:
            response = httpx.get(url, params=params, headers=headers, timeout=self.timeout_seconds)
            return response.status_code, dict(response.headers), response.text
        if requests is not None:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=self.timeout_seconds,
            )
            return response.status_code, dict(response.headers), response.text

        query = urllib.parse.urlencode(params)
        full_url = f"{url}?{query}"
        request = urllib.request.Request(full_url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8")
                return response.status, dict(response.headers), body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8") if exc.fp else ""
            return exc.code, dict(exc.headers), body

    @staticmethod
    def _parse_retry_after(value: str | None) -> float | None:
        if not value:
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _sleep_backoff(attempt: int, retry_after: float | None = None) -> None:
        backoff = min(8.0, 0.5 * (2 ** attempt))
        delay = retry_after if retry_after is not None else backoff
        time.sleep(delay)
