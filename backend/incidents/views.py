from django.db import transaction
from django.db.models import Q
from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view
from rest_framework.response import Response

from incidents.models import AttackIncident
from incidents.serializers import (
    AttackIncidentCreateSerializer,
    AttackIncidentReadSerializer,
    AttackIncidentStatusSerializer,
)
from incidents.services.jira import (
    JiraIntegrationError,
    JiraIntegrationUnavailable,
    JiraIntegrationValidationError,
    create_jira_ticket_for_incident_from_db,
)
from incidents.services.notifications import notify_slack_incident_created
from incidents.threat_intel_service import lookup_ip_reputation


class AttackIncidentViewSet(viewsets.ModelViewSet):
    queryset = AttackIncident.objects.all()

    def get_serializer_class(self):
        if self.action in {"list", "retrieve"}:
            return AttackIncidentReadSerializer
        return AttackIncidentCreateSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        incident = serializer.instance
        if incident is not None:
            transaction.on_commit(lambda: notify_slack_incident_created(incident))
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

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

    @action(detail=True, methods=["post"], url_path="jira/create")
    def create_jira_ticket(self, request, pk=None):
        return _handle_jira_ticket_create(pk)

    @action(detail=True, methods=["patch"], url_path="status")
    def update_status(self, request, pk=None):
        incident = self.get_object()
        serializer = AttackIncidentStatusSerializer(incident, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(AttackIncidentReadSerializer(incident).data)


def _handle_jira_ticket_create(incident_id):
    try:
        result = create_jira_ticket_for_incident_from_db(incident_id)
    except JiraIntegrationUnavailable as exc:
        return Response(
            {"detail": "Jira integration is disabled or unavailable.", "error": str(exc)},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    except JiraIntegrationValidationError as exc:
        return Response(
            {"detail": "Incident title/summary not set on incident.", "error": str(exc)},
            status=422,
        )
    except JiraIntegrationError as exc:
        return Response(
            {"detail": "Failed to create Jira issue.", "error": str(exc)},
            status=status.HTTP_502_BAD_GATEWAY,
        )

    return Response(
        {
            "incident_id": str(incident_id),
            "jira_issue_key": result.get("jira_issue_key"),
            "jira_issue_url": result.get("jira_issue_url"),
        }
    )


@api_view(["GET"])
def threat_intel_ip_view(request, ip: str):
    params = request.query_params
    max_age_days = params.get("max_age_days")
    if max_age_days is not None and max_age_days != "":
        try:
            max_age_days = int(max_age_days)
        except (TypeError, ValueError):
            max_age_days = None
    else:
        max_age_days = None

    verbose = str(params.get("verbose", "false")).lower() in {"1", "true", "yes", "on"}
    result = lookup_ip_reputation(ip=ip, max_age_days=max_age_days, verbose=verbose)
    return Response(result)
