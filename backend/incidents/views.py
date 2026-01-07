from django.db.models import Q
from rest_framework import viewsets

from incidents.models import AttackIncident
from incidents.serializers import AttackIncidentSerializer


class AttackIncidentViewSet(viewsets.ModelViewSet):
    queryset = AttackIncident.objects.all()
    serializer_class = AttackIncidentSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        params = self.request.query_params

        status = params.get("status")
        if status:
            qs = qs.filter(status=status)

        attack_type = params.get("attack_type")
        if attack_type:
            qs = qs.filter(attack_type=attack_type)

        min_severity = params.get("min_severity")
        if min_severity is not None and min_severity != "":
            try:
                min_severity_val = int(min_severity)
            except (TypeError, ValueError):
                min_severity_val = None
            if min_severity_val is not None:
                qs = qs.filter(severity__gte=min_severity_val)

        query = params.get("q")
        if query:
            qs = qs.filter(
                Q(title__icontains=query)
                | Q(source_ip__icontains=query)
                | Q(dest_ip__icontains=query)
                | Q(asset__icontains=query)
            )

        ordering = params.get("ordering") or "-last_seen_at"
        allowed_fields = {
            "first_seen_at",
            "last_seen_at",
            "severity",
            "status",
            "attack_type",
            "created_at",
            "updated_at",
        }
        ordering_fields = []
        for field in ordering.split(","):
            field = field.strip()
            if not field:
                continue
            desc = field.startswith("-")
            raw_field = field[1:] if desc else field
            if raw_field in allowed_fields:
                ordering_fields.append(field)
        if ordering_fields:
            qs = qs.order_by(*ordering_fields)
        else:
            qs = qs.order_by("-last_seen_at")
        return qs
