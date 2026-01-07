import uuid

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models
import django.db.models.expressions


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AttackIncident",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("first_seen_at", models.DateTimeField(db_index=True)),
                ("last_seen_at", models.DateTimeField(db_index=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("title", models.CharField(max_length=120)),
                (
                    "attack_type",
                    models.CharField(
                        choices=[
                            ("ddos", "ddos"),
                            ("port_scan", "port_scan"),
                            ("bruteforce", "bruteforce"),
                            ("malware", "malware"),
                            ("unknown", "unknown"),
                        ],
                        db_index=True,
                        max_length=50,
                    ),
                ),
                (
                    "severity",
                    models.SmallIntegerField(
                        db_index=True,
                        validators=[MinValueValidator(0), MaxValueValidator(100)],
                    ),
                ),
                (
                    "confidence",
                    models.SmallIntegerField(
                        blank=True,
                        null=True,
                        validators=[MinValueValidator(0), MaxValueValidator(100)],
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("open", "open"),
                            ("mitigated", "mitigated"),
                            ("false_positive", "false_positive"),
                            ("ignored", "ignored"),
                        ],
                        db_index=True,
                        max_length=20,
                    ),
                ),
                ("source_ip", models.GenericIPAddressField()),
                ("source_port", models.IntegerField(blank=True, null=True)),
                ("dest_ip", models.GenericIPAddressField()),
                ("dest_port", models.IntegerField(blank=True, null=True)),
                (
                    "protocol",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("tcp", "tcp"),
                            ("udp", "udp"),
                            ("icmp", "icmp"),
                            ("other", "other"),
                        ],
                        max_length=10,
                    ),
                ),
                ("asset", models.CharField(blank=True, max_length=120)),
                ("tags", models.JSONField(blank=True, default=list)),
                ("evidence", models.JSONField(blank=True, default=dict)),
                ("summary", models.TextField(blank=True)),
                ("action_taken", models.CharField(blank=True, max_length=50)),
                ("external_refs", models.JSONField(blank=True, default=dict)),
            ],
            options={
                "indexes": [
                    models.Index(fields=["source_ip", "dest_ip", "dest_port"], name="incidents_sourc_f0e5d9_idx"),
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="attackincident",
            constraint=models.CheckConstraint(
                check=models.Q(
                    ("last_seen_at__gte", django.db.models.expressions.F("first_seen_at"))
                ),
                name="incident_last_seen_gte_first_seen",
            ),
        ),
    ]
