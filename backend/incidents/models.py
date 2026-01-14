import uuid

from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models


class AttackType(models.TextChoices):
    DDOS = "ddos", "ddos"
    PORT_SCAN = "port_scan", "port_scan"
    BRUTEFORCE = "bruteforce", "bruteforce"
    MALWARE = "malware", "malware"
    UNKNOWN = "unknown", "unknown"


class IncidentStatus(models.TextChoices):
    OPEN = "open", "open"
    MITIGATED = "mitigated", "mitigated"
    FALSE_POSITIVE = "false_positive", "false_positive"
    IGNORED = "ignored", "ignored"


class IncidentProtocol(models.TextChoices):
    TCP = "tcp", "tcp"
    UDP = "udp", "udp"
    ICMP = "icmp", "icmp"
    OTHER = "other", "other"


class AttackIncident(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_seen_at = models.DateTimeField(db_index=True)
    last_seen_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    title = models.CharField(max_length=120)
    attack_type = models.CharField(max_length=50, choices=AttackType.choices, db_index=True)
    severity = models.SmallIntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        db_index=True,
    )
    confidence = models.SmallIntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    status = models.CharField(max_length=20, choices=IncidentStatus.choices, db_index=True)
    source_ip = models.GenericIPAddressField()
    source_port = models.IntegerField(null=True, blank=True)
    dest_ip = models.GenericIPAddressField()
    dest_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=10, choices=IncidentProtocol.choices, blank=True)
    asset = models.CharField(max_length=120, blank=True)
    tags = models.JSONField(default=list, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    summary = models.TextField(blank=True)
    action_taken = models.CharField(max_length=50, blank=True)
    external_refs = models.JSONField(default=dict, blank=True)
    jira_issue_key = models.CharField(max_length=50, null=True, blank=True, db_index=True)
    jira_issue_url = models.URLField(null=True, blank=True)
    jira_created_at = models.DateTimeField(null=True, blank=True)
    last_jira_error = models.TextField(null=True, blank=True)
    slack_notified_at = models.DateTimeField(null=True, blank=True)
    last_slack_error = models.TextField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["source_ip", "dest_ip", "dest_port"]),
        ]
        constraints = [
            models.CheckConstraint(
                check=models.Q(last_seen_at__gte=models.F("first_seen_at")),
                name="incident_last_seen_gte_first_seen",
            ),
        ]

    def clean(self) -> None:
        if self.first_seen_at and self.last_seen_at and self.last_seen_at < self.first_seen_at:
            raise ValidationError({"last_seen_at": "last_seen_at must be >= first_seen_at."})

    def __str__(self) -> str:
        return self.title
