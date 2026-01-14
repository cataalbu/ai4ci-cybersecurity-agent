import logging

from django.conf import settings
from django.utils import timezone

from incidents.models import AttackIncident

logger = logging.getLogger(__name__)


class JiraIntegrationError(Exception):
    pass


class JiraIntegrationUnavailable(JiraIntegrationError):
    pass


class JiraIntegrationValidationError(JiraIntegrationError):
    pass


def create_jira_ticket_for_incident_from_db(incident_id):
    from integrations.jira.client import (
        JiraClient,
        JiraClientError,
        JiraClientUnavailable,
        JiraValidationError,
    )

    jira_settings = getattr(settings, "JIRA", {}) or {}
    if not jira_settings.get("enabled"):
        raise JiraIntegrationUnavailable("jira_disabled")

    incident = AttackIncident.objects.get(id=incident_id)

    if incident.jira_issue_key:
        return {
            "jira_issue_key": incident.jira_issue_key,
            "jira_issue_url": incident.jira_issue_url,
        }

    summary = (incident.title or "").strip()
    description = (incident.summary or "").strip()
    if not summary or not description:
        incident.last_jira_error = "missing_incident_title_or_summary"
        incident.save(update_fields=["last_jira_error", "updated_at"])
        raise JiraIntegrationValidationError("missing_incident_title_or_summary")

    client = JiraClient(
        base_url=jira_settings["base_url"],
        email=jira_settings["email"],
        api_token=jira_settings["api_token"],
        project_key=jira_settings["project_key"],
        issue_type=jira_settings.get("issue_type") or "Incident",
        timeout_seconds=jira_settings.get("timeout_seconds") or 10,
        retries=jira_settings.get("retries") or 2,
    )

    try:
        issue = client.create_issue(
            summary=summary,
            description=description,
            labels=jira_settings.get("labels") or [],
            priority=jira_settings.get("default_priority"),
            custom_fields=None,
        )
    except JiraValidationError as exc:
        incident.last_jira_error = str(exc)
        incident.save(update_fields=["last_jira_error", "updated_at"])
        raise JiraIntegrationValidationError(str(exc)) from exc
    except JiraClientUnavailable as exc:
        incident.last_jira_error = str(exc)
        incident.save(update_fields=["last_jira_error", "updated_at"])
        raise JiraIntegrationUnavailable(str(exc)) from exc
    except JiraClientError as exc:
        incident.last_jira_error = str(exc)
        incident.save(update_fields=["last_jira_error", "updated_at"])
        raise JiraIntegrationError(str(exc)) from exc

    incident.jira_issue_key = issue.get("key")
    incident.jira_issue_url = issue.get("url")
    incident.jira_created_at = timezone.now()
    incident.last_jira_error = ""
    incident.save(
        update_fields=[
            "jira_issue_key",
            "jira_issue_url",
            "jira_created_at",
            "last_jira_error",
            "updated_at",
        ]
    )

    logger.info(
        "jira_issue_created",
        extra={
            "incident_id": str(incident.id),
            "jira_issue_key": incident.jira_issue_key,
        },
    )

    return {
        "jira_issue_key": incident.jira_issue_key,
        "jira_issue_url": incident.jira_issue_url,
    }
