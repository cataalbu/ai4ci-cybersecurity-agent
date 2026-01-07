import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from incidents.models import AttackIncident, AttackType, IncidentProtocol, IncidentStatus


class Command(BaseCommand):
    help = "Seed the database with sample attack incidents."

    def handle(self, *args, **options):
        rng = random.Random(7)
        now = timezone.now()
        titles = [
            "Port scan from 203.0.113.5",
            "Bruteforce login attempts against admin",
            "Suspicious DNS exfiltration spike",
            "Malware beacon detected",
            "API enumeration activity",
            "DDoS burst on /health endpoint",
        ]
        source_ips = ["203.0.113.5", "198.51.100.23", "192.0.2.45", "203.0.113.77"]
        dest_ips = ["10.0.0.5", "10.0.0.10", "10.0.1.12"]
        protocols = [IncidentProtocol.TCP, IncidentProtocol.UDP, IncidentProtocol.ICMP]

        created = 0
        for idx in range(10):
            first_seen = now - timedelta(minutes=rng.randint(10, 600))
            last_seen = first_seen + timedelta(minutes=rng.randint(1, 45))
            AttackIncident.objects.create(
                title=rng.choice(titles),
                attack_type=rng.choice(AttackType.values),
                severity=rng.randint(10, 95),
                confidence=rng.choice([None, rng.randint(40, 100)]),
                status=rng.choice(IncidentStatus.values),
                source_ip=rng.choice(source_ips),
                source_port=rng.choice([None, 22, 80, 443, 3389, 8080]),
                dest_ip=rng.choice(dest_ips),
                dest_port=rng.choice([None, 22, 80, 443, 3389, 8080]),
                protocol=rng.choice(protocols).value,
                asset=rng.choice(["web-1", "api-1", "db-1", "auth-1", ""]),
                tags=["auto", "seed", f"batch-{idx // 3}"],
                evidence={"notes": "seeded incident", "sample": True},
                summary="Seeded incident for local development.",
                action_taken=rng.choice(["none", "blocked", "throttled", "ticketed"]),
                external_refs={"jira": f"SEC-{100 + idx}"},
                first_seen_at=first_seen,
                last_seen_at=last_seen,
            )
            created += 1

        self.stdout.write(self.style.SUCCESS(f"Inserted {created} incidents."))
