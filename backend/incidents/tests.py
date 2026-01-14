from unittest.mock import patch

from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from incidents.models import AttackIncident
from incidents.services.jira import (
    JiraIntegrationValidationError,
    create_jira_ticket_for_incident_from_db,
)
from integrations.slack.client import (
    _format_iso_utc,
    _truncate_text,
    post_incident_created_message,
)
from integrations.jira.client import JiraClient


def _jira_settings():
    return {
        "enabled": True,
        "base_url": "https://example.atlassian.net",
        "email": "user@example.com",
        "api_token": "token",
        "project_key": "NDR",
        "issue_type": "Incident",
        "default_priority": None,
        "labels": ["ai-agent"],
        "timeout_seconds": 1,
        "retries": 0,
    }


def _create_incident(**overrides):
    now = timezone.now()
    defaults = {
        "first_seen_at": now,
        "last_seen_at": now,
        "title": "Test Incident",
        "attack_type": "port_scan",
        "severity": 50,
        "confidence": 80,
        "status": "open",
        "source_ip": "8.8.8.8",
        "source_port": 1234,
        "dest_ip": "1.1.1.1",
        "dest_port": 80,
        "protocol": "tcp",
        "asset": "web-01",
        "summary": "LLM summary text",
    }
    defaults.update(overrides)
    return AttackIncident.objects.create(**defaults)


class JiraIntegrationTests(TestCase):
    @override_settings(JIRA=_jira_settings())
    @patch("incidents.services.jira.JiraClient.create_issue")
    def test_jira_uses_db_fields(self, mock_create_issue):
        incident = _create_incident(title="New incident: port_scan - 8.8.8.8", summary="LLM summary text")
        mock_create_issue.return_value = {
            "key": "NDR-1",
            "url": "https://example.atlassian.net/browse/NDR-1",
        }

        result = create_jira_ticket_for_incident_from_db(incident.id)

        mock_create_issue.assert_called_once()
        _, kwargs = mock_create_issue.call_args
        self.assertEqual(kwargs["summary"], "New incident: port_scan - 8.8.8.8")
        self.assertEqual(kwargs["description"], "LLM summary text")
        self.assertEqual(result["jira_issue_key"], "NDR-1")

    @override_settings(JIRA=_jira_settings())
    def test_summary_required(self):
        incident = _create_incident(summary="")
        with self.assertRaises(JiraIntegrationValidationError):
            create_jira_ticket_for_incident_from_db(incident.id)

    @override_settings(JIRA=_jira_settings())
    @patch("incidents.services.jira.JiraClient.create_issue")
    def test_jira_idempotent_when_key_exists(self, mock_create_issue):
        incident = _create_incident(jira_issue_key="NDR-9", jira_issue_url="https://jira/browse/NDR-9")

        result = create_jira_ticket_for_incident_from_db(incident.id)

        self.assertEqual(result["jira_issue_key"], "NDR-9")
        self.assertEqual(result["jira_issue_url"], "https://jira/browse/NDR-9")
        mock_create_issue.assert_not_called()

    @patch("integrations.jira.client.requests.post")
    def test_adf_description_wrapping(self, mock_post):
        payload_holder = {}

        class MockResponse:
            status_code = 201
            headers = {}

            def json(self):
                return {"key": "NDR-2", "id": "200", "self": "http://jira/issue/200"}

        def _capture_post(*args, **kwargs):
            payload_holder["json"] = kwargs.get("json")
            return MockResponse()

        mock_post.side_effect = _capture_post

        client = JiraClient(
            base_url="https://example.atlassian.net",
            email="user@example.com",
            api_token="token",
            project_key="NDR",
            issue_type="Incident",
            timeout_seconds=1,
            retries=0,
        )
        client.create_issue(
            summary="New incident: port_scan - 8.8.8.8",
            description="LLM summary text",
            labels=["ai-agent"],
            priority=None,
            custom_fields=None,
        )

        sent = payload_holder["json"]
        self.assertEqual(sent["fields"]["summary"], "New incident: port_scan - 8.8.8.8")
        self.assertEqual(
            sent["fields"]["description"],
            {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": "LLM summary text",
                            }
                        ],
                    }
                ],
            },
        )


class JiraEndpointTests(TestCase):
    @override_settings(JIRA=_jira_settings())
    @patch("incidents.views.create_jira_ticket_for_incident_from_db")
    def test_jira_endpoint(self, mock_create):
        incident = _create_incident()
        mock_create.return_value = {
            "jira_issue_key": "NDR-3",
            "jira_issue_url": "https://example.atlassian.net/browse/NDR-3",
        }

        client = APIClient()
        response = client.post(f"/api/incidents/{incident.id}/jira/create/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["jira_issue_key"], "NDR-3")

    @override_settings(JIRA=_jira_settings())
    def test_jira_endpoint_requires_db_fields(self):
        incident = _create_incident(title="", summary="")
        client = APIClient()
        response = client.post(f"/api/incidents/{incident.id}/jira/create/")

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.data["detail"], "Incident title/summary not set on incident.")

    def test_create_incident_requires_summary(self):
        client = APIClient()
        payload = {
            "first_seen_at": timezone.now().isoformat(),
            "last_seen_at": timezone.now().isoformat(),
            "title": "Test Incident",
            "attack_type": "port_scan",
            "severity": 50,
            "status": "open",
            "source_ip": "8.8.8.8",
            "dest_ip": "1.1.1.1",
        }
        response = client.post("/api/incidents/", payload, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertIn("summary", response.data)

    @patch("integrations.jira.client.JiraClient.create_issue")
    def test_create_incident_does_not_call_jira(self, mock_create_issue):
        client = APIClient()
        payload = {
            "first_seen_at": timezone.now().isoformat(),
            "last_seen_at": timezone.now().isoformat(),
            "title": "Test Incident",
            "attack_type": "port_scan",
            "severity": 50,
            "status": "open",
            "source_ip": "8.8.8.8",
            "dest_ip": "1.1.1.1",
            "summary": "LLM summary text",
        }
        response = client.post("/api/incidents/", payload, format="json")

        self.assertEqual(response.status_code, 201)
        mock_create_issue.assert_not_called()


class IncidentStatusUpdateTests(TestCase):
    def test_patch_status_updates_incident(self):
        incident = _create_incident(status="open")
        client = APIClient()
        response = client.patch(
            f"/api/incidents/{incident.id}/status/",
            {"status": "mitigated"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        incident.refresh_from_db()
        self.assertEqual(incident.status, "mitigated")


def _slack_settings():
    return {
        "enabled": True,
        "bot_token": "xoxb-test",
        "channel_id": "C123456",
        "icon_emoji": ":shield:",
        "bot_name": "NDR Bot",
    }


class SlackNotificationTests(TransactionTestCase):
    def _payload(self, **overrides):
        now = timezone.now()
        payload = {
            "first_seen_at": now.isoformat(),
            "last_seen_at": now.isoformat(),
            "title": "New incident: brute_force - 203.0.113.45",
            "attack_type": "bruteforce",
            "severity": 70,
            "status": "open",
            "source_ip": "8.8.8.8",
            "dest_ip": "1.1.1.1",
            "summary": "Bruteforce activity detected on SSH.",
        }
        payload.update(overrides)
        return payload

    @override_settings(SLACK=_slack_settings())
    @patch("incidents.services.notifications.post_incident_created_message")
    def test_create_incident_triggers_slack(self, mock_post):
        client = APIClient()
        response = client.post("/api/incidents/", self._payload(), format="json")

        self.assertEqual(response.status_code, 201)
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["title"], "New incident: brute_force - 203.0.113.45")
        self.assertEqual(kwargs["description"], "Bruteforce activity detected on SSH.")

    @override_settings(SLACK=_slack_settings())
    @patch("incidents.services.notifications.post_incident_created_message")
    def test_slack_failure_does_not_break_create(self, mock_post):
        mock_post.side_effect = Exception("boom")
        client = APIClient()
        response = client.post("/api/incidents/", self._payload(), format="json")

        self.assertEqual(response.status_code, 201)
        self.assertEqual(AttackIncident.objects.count(), 1)

    @override_settings(SLACK={"enabled": False})
    @patch("incidents.services.notifications.post_incident_created_message")
    def test_slack_disabled_skips_notification(self, mock_post):
        client = APIClient()
        response = client.post("/api/incidents/", self._payload(), format="json")

        self.assertEqual(response.status_code, 201)
        mock_post.assert_not_called()


class SlackClientFormatTests(TestCase):
    @override_settings(SLACK=_slack_settings())
    @patch("integrations.slack.client.WebClient.chat_postMessage")
    def test_post_incident_message_blocks(self, mock_post):
        captured = {}

        class MockResponse:
            data = {"ok": True}

        def _capture(*args, **kwargs):
            captured.update(kwargs)
            return MockResponse()

        mock_post.side_effect = _capture

        post_incident_created_message(
            title="New incident: brute_force - 203.0.113.45",
            description="Description here",
            incident_id="42",
            created_at=timezone.datetime(2026, 1, 8, 14, 32, 10),
        )

        blocks = captured.get("blocks")
        self.assertEqual(blocks[0]["text"]["text"], "🚨 New Incident Created")
        self.assertEqual(blocks[1]["text"]["text"], "*New incident: brute_force - 203.0.113.45*")
        self.assertEqual(blocks[2]["text"]["text"], "Description here")

    def test_truncate_text(self):
        self.assertEqual(_truncate_text("abc", 10), "abc")
        self.assertEqual(_truncate_text("abcd", 3), "abc")
        self.assertEqual(_truncate_text("abcd", 4), "abcd")
        self.assertEqual(_truncate_text("abcdef", 5), "ab...")

    def test_format_iso_utc(self):
        value = timezone.datetime(2026, 1, 8, 14, 32, 10)
        self.assertEqual(_format_iso_utc(value), "2026-01-08T14:32:10Z")
