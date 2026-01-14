from rest_framework.decorators import api_view
from rest_framework.response import Response

from threat_intel.threat_intel_service import lookup_ip_reputation


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
