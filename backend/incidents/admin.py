from django.contrib import admin

from incidents.models import AttackIncident


@admin.register(AttackIncident)
class AttackIncidentAdmin(admin.ModelAdmin):
    list_display = ("title", "attack_type", "severity", "status", "last_seen_at")
    search_fields = ("title", "source_ip", "dest_ip", "asset")
    list_filter = ("status", "attack_type")
