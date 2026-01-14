from django.urls import path

from threat_intel.views import threat_intel_ip_view

urlpatterns = [
    path("threat-intel/ip/<path:ip>", threat_intel_ip_view, name="threat-intel-ip"),
]
