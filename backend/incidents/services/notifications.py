import logging

from django.conf import settings
from django.utils import timezone

from incidents.models import AttackIncident
from integrations.slack.client import SlackClientError, post_incident_created_message

logger = logging.getLogger(__name__)


def notify_slack_incident_created(incident: AttackIncident) -> None:
    slack_settings = getattr(settings, "SLACK", {}) or {}
    if not slack_settings.get("enabled"):
        return

    title = (incident.title or "").strip()
    description = (incident.summary or "").strip()
    if not title or not description:
        incident.last_slack_error = "missing_incident_title_or_summary"
        incident.save(update_fields=["last_slack_error", "updated_at"])
        return

    try:
        post_incident_created_message(
            title=title,
            description=description,
            severity=str(incident.severity),
            incident_id=str(incident.id),
            created_at=incident.created_at or timezone.now(),
        )
    except SlackClientError as exc:
        incident.last_slack_error = str(exc)
        incident.save(update_fields=["last_slack_error", "updated_at"])
        logger.exception(
            "slack_notification_failed",
            extra={"incident_id": str(incident.id), "error": str(exc)},
        )
        return
    except Exception as exc:
        incident.last_slack_error = "slack_unknown_error"
        incident.save(update_fields=["last_slack_error", "updated_at"])
        logger.exception(
            "slack_notification_failed",
            extra={"incident_id": str(incident.id), "error": str(exc)},
        )
        return

    incident.slack_notified_at = timezone.now()
    incident.last_slack_error = ""
    incident.save(update_fields=["slack_notified_at", "last_slack_error", "updated_at"])
