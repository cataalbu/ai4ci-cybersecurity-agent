from rest_framework import serializers

from incidents.models import AttackIncident


class AttackIncidentSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackIncident
        fields = "__all__"

    def validate(self, attrs):
        instance = getattr(self, "instance", None)
        first_seen_at = attrs.get("first_seen_at") or (instance.first_seen_at if instance else None)
        last_seen_at = attrs.get("last_seen_at") or (instance.last_seen_at if instance else None)
        if first_seen_at and last_seen_at and last_seen_at < first_seen_at:
            raise serializers.ValidationError(
                {"last_seen_at": "last_seen_at must be greater than or equal to first_seen_at."}
            )
        return attrs
