from rest_framework import serializers

from incidents.models import AttackIncident


class AttackIncidentReadSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackIncident
        fields = "__all__"


class AttackIncidentCreateSerializer(serializers.ModelSerializer):
    summary = serializers.CharField(allow_blank=False, trim_whitespace=True)
    class Meta:
        model = AttackIncident
        fields = "__all__"
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "jira_issue_key",
            "jira_issue_url",
            "jira_created_at",
            "last_jira_error",
            "slack_notified_at",
            "last_slack_error",
        ]

    def validate(self, attrs):
        instance = getattr(self, "instance", None)
        first_seen_at = attrs.get("first_seen_at") or (instance.first_seen_at if instance else None)
        last_seen_at = attrs.get("last_seen_at") or (instance.last_seen_at if instance else None)
        if first_seen_at and last_seen_at and last_seen_at < first_seen_at:
            raise serializers.ValidationError(
                {"last_seen_at": "last_seen_at must be greater than or equal to first_seen_at."}
            )
        return attrs


class AttackIncidentStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackIncident
        fields = ["status"]
