import logging
import time
from dataclasses import dataclass

import requests

logger = logging.getLogger(__name__)


class JiraClientError(Exception):
    pass


class JiraClientUnavailable(JiraClientError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class JiraValidationError(JiraClientError):
    pass


class JiraIssueTypeNotFound(JiraValidationError):
    pass


@dataclass(frozen=True)
class JiraClient:
    base_url: str
    email: str
    api_token: str
    project_key: str
    issue_type: str
    timeout_seconds: int = 10
    retries: int = 2

    def create_issue(
        self,
        summary: str,
        description: str,
        labels: list[str],
        priority: str | None = None,
        custom_fields: dict | None = None,
    ) -> dict:
        if not description or not str(description).strip():
            raise JiraValidationError("missing_description")

        try:
            return self._create_issue_with_type(
                issue_type=self.issue_type,
                summary=summary,
                description=description,
                labels=labels,
                priority=priority,
                custom_fields=custom_fields,
            )
        except JiraIssueTypeNotFound:
            if self.issue_type == "Task":
                raise
            fallback_client = JiraClient(
                base_url=self.base_url,
                email=self.email,
                api_token=self.api_token,
                project_key=self.project_key,
                issue_type="Task",
                timeout_seconds=self.timeout_seconds,
                retries=self.retries,
            )
            return fallback_client._create_issue_with_type(
                issue_type="Task",
                summary=summary,
                description=description,
                labels=labels,
                priority=priority,
                custom_fields=custom_fields,
            )

    def _create_issue_with_type(
        self,
        issue_type: str,
        summary: str,
        description: str,
        labels: list[str],
        priority: str | None,
        custom_fields: dict | None,
    ) -> dict:
        url = f"{self.base_url.rstrip('/')}/rest/api/3/issue"
        fields: dict = {
            "project": {"key": self.project_key},
            "summary": summary,
            "issuetype": {"name": issue_type},
            "description": self._build_adf_description(description),
        }
        if labels:
            fields["labels"] = labels
        if priority:
            fields["priority"] = {"name": priority}
        if custom_fields:
            fields.update(custom_fields)

        payload = {"fields": fields}
        response = self._post_json(url, payload)
        key = response.get("key")
        if not key:
            raise JiraClientError("missing_issue_key")
        return {
            "key": key,
            "id": response.get("id"),
            "self": response.get("self"),
            "url": f"{self.base_url.rstrip('/')}/browse/{key}",
        }

    def _post_json(self, url: str, payload: dict) -> dict:
        last_error = None
        for attempt in range(self.retries + 1):
            try:
                response = requests.post(
                    url,
                    auth=(self.email, self.api_token),
                    json=payload,
                    timeout=self.timeout_seconds,
                )
            except requests.RequestException as exc:
                last_error = exc
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    continue
                raise JiraClientError("network_error") from exc

            status = response.status_code
            if 200 <= status < 300:
                return response.json()

            body = {}
            try:
                body = response.json()
            except ValueError:
                body = {}

            if status in (401, 403):
                raise JiraClientUnavailable("auth_failed")
            if status == 429:
                if attempt < self.retries:
                    retry_after = self._parse_retry_after(response.headers.get("Retry-After"))
                    self._sleep_backoff(attempt, retry_after)
                    continue
                raise JiraClientUnavailable("rate_limited")
            if 400 <= status < 500:
                self._log_client_error(status, body)
                if self._is_issue_type_error(body):
                    raise JiraIssueTypeNotFound("issue_type_not_found")
                raise JiraValidationError(f"client_error:{status}")
            if status >= 500:
                if attempt < self.retries:
                    self._sleep_backoff(attempt)
                    continue
                raise JiraClientUnavailable(f"server_error:{status}")

            last_error = body or {"status": status}

        raise JiraClientError(f"unexpected_retry_exhaustion:{last_error}")

    @staticmethod
    def _build_adf_description(text: str) -> dict:
        return {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "type": "text",
                            "text": text,
                        }
                    ],
                }
            ],
        }

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

    @staticmethod
    def _is_issue_type_error(body: dict) -> bool:
        errors = body.get("errors") if isinstance(body, dict) else None
        if isinstance(errors, dict):
            issue_error = errors.get("issuetype") or ""
            if issue_error:
                return True
        messages = body.get("errorMessages") if isinstance(body, dict) else None
        if isinstance(messages, list):
            for message in messages:
                if isinstance(message, str) and "issue type" in message.lower():
                    return True
        return False

    @staticmethod
    def _log_client_error(status: int, body: dict) -> None:
        logger.warning(
            "jira_client_error",
            extra={
                "status": status,
                "errors": body.get("errors") if isinstance(body, dict) else None,
            },
        )
