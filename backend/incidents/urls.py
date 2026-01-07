from django.urls import include, path
from rest_framework.routers import DefaultRouter

from incidents.views import AttackIncidentViewSet

router = DefaultRouter()
router.register("incidents", AttackIncidentViewSet, basename="incidents")

urlpatterns = [
    path("", include(router.urls)),
]
