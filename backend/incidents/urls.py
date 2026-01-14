from django.urls import include, path
from rest_framework.routers import DefaultRouter

from incidents.views import AttackIncidentViewSet, threat_intel_ip_view

router = DefaultRouter()
router.register("incidents", AttackIncidentViewSet, basename="incidents")

urlpatterns = [
    path("threat-intel/ip/<path:ip>", threat_intel_ip_view, name="threat-intel-ip"),
    path("", include(router.urls)),
]
