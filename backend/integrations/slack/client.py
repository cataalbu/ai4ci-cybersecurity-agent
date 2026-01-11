import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from django.conf import settings
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

logger = logging.getLogger(__name__)

_SLACK_TEXT_LIMIT = 3000


class SlackClientError(Exception):
    pass


@dataclass(frozen=True)
class SlackClientConfig:
    token: str
    channel_id: str
    icon_emoji: str | None
    bot_name: str | None
    timeout_seconds: int = 10


def post_incident_created_message(
    *,
    title: str,
    description: str,
    severity: str,
    incident_id: str | int,
    created_at: datetime,
) -> dict:
    slack_settings = getattr(settings, "SLACK", {}) or {}
    config = SlackClientConfig(
        token=slack_settings.get("bot_token"),
        channel_id=slack_settings.get("channel_id"),
        icon_emoji=slack_settings.get("icon_emoji"),
        bot_name=slack_settings.get("bot_name"),
        timeout_seconds=10,
    )
    if not config.token or not config.channel_id:
        raise SlackClientError("slack_not_configured")

    created_at_iso = _format_iso_utc(created_at)
    safe_description = _truncate_text(description, _SLACK_TEXT_LIMIT)
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 New Incident Created",
                "emoji": True,
            },
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": safe_description}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"Severity: *{severity}*"}},
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Incident ID: {incident_id} • Created at: {created_at_iso}",
                }
            ],
        },
    ]

    client = WebClient(token=config.token, timeout=config.timeout_seconds)
    try:
        response = client.chat_postMessage(
            channel=config.channel_id,
            text="New incident created",
            blocks=blocks,
            icon_emoji=config.icon_emoji,
            username=config.bot_name,
        )
    except SlackApiError as exc:
        error_code = exc.response.get("error") if exc.response else "slack_api_error"
        raise SlackClientError(error_code) from exc
    except Exception as exc:
        raise SlackClientError("slack_client_error") from exc

    return response.data


def _format_iso_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    utc_value = value.astimezone(timezone.utc).replace(microsecond=0)
    return utc_value.isoformat().replace("+00:00", "Z")


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3].rstrip() + "..."
