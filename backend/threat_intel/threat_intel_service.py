import ipaddress
import logging
import time
from collections import OrderedDict

from django.conf import settings

from threat_intel.abuseipdb_client import AbuseIpDbClient, AbuseIpDbError, AbuseIpDbUnavailable

logger = logging.getLogger(__name__)

_LOCAL_CACHE_MAXSIZE = 1024


class _LocalTTLCache:
    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._data: OrderedDict[str, tuple[dict, float]] = OrderedDict()

    def get(self, key: str) -> dict | None:
        item = self._data.get(key)
        if not item:
            return None
        value, expires_at = item
        if expires_at < time.time():
            self._data.pop(key, None)
            return None
        self._data.move_to_end(key)
        return value

    def set(self, key: str, value: dict, ttl_seconds: int) -> None:
        expires_at = time.time() + ttl_seconds
        self._data[key] = (value, expires_at)
        self._data.move_to_end(key)
        while len(self._data) > self._maxsize:
            self._data.popitem(last=False)


try:
    from cachetools import TTLCache

    _local_cache_backend = TTLCache(
        maxsize=_LOCAL_CACHE_MAXSIZE,
        ttl=settings.ABUSEIPDB_CACHE_TTL_SECONDS,
    )
    _use_cachetools = True
except Exception:
    _local_cache_backend = _LocalTTLCache(_LOCAL_CACHE_MAXSIZE)
    _use_cachetools = False


def _get_cache_backend():
    if getattr(settings, "CACHES", None):
        try:
            from django.core.cache import cache as django_cache

            return "django", django_cache
        except Exception:
            pass
    return "local", _local_cache_backend


def _cache_get(key: str) -> dict | None:
    backend_type, backend = _get_cache_backend()
    if backend_type == "django":
        return backend.get(key)
    return backend.get(key)


def _cache_set(key: str, value: dict, ttl_seconds: int) -> None:
    backend_type, backend = _get_cache_backend()
    if backend_type == "django":
        backend.set(key, value, timeout=ttl_seconds)
        return
    if _use_cachetools:
        backend[key] = value
        return
    backend.set(key, value, ttl_seconds)


def _is_public_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return parsed.is_global


def _base_result(ip: str) -> dict:
    return {
        "indicator": ip,
        "indicator_type": "ip",
        "source": "abuseipdb",
        "status": "ok",
        "found": True,
        "reputation": "unknown",
        "confidence": 0.0,
        "abuse_confidence_score": 0,
        "total_reports": 0,
        "distinct_reporters": 0,
        "last_reported_at": None,
        "is_whitelisted": False,
        "context": {
            "country_code": None,
            "usage_type": None,
            "isp": None,
            "domain": None,
            "hostnames": [],
        },
        "evidence": [],
        "raw": None,
    }


def lookup_ip_reputation(
    ip: str,
    max_age_days: int | None = None,
    verbose: bool = False,
) -> dict:
    if not _is_public_ip(ip):
        result = _base_result(ip)
        result.update(
            {
                "status": "not_applicable",
                "found": False,
                "reputation": "not_applicable",
                "confidence": 0.0,
            }
        )
        return result

    max_age = max_age_days if max_age_days is not None else settings.ABUSEIPDB_MAX_AGE_DAYS
    cache_key = f"abuseipdb:check:{ip}:{max_age}:{int(verbose)}"
    cached = _cache_get(cache_key)
    if cached:
        logger.info(
            "threat_intel_lookup",
            extra={
                "ip": ip,
                "status": cached.get("status"),
                "score": cached.get("abuse_confidence_score"),
                "cache_hit": True,
            },
        )
        return cached

    if not settings.ABUSEIPDB_API_KEY:
        result = _base_result(ip)
        result.update(
            {
                "status": "unavailable",
                "found": False,
                "reputation": "unknown",
                "confidence": 0.0,
            }
        )
        result["evidence"].append("reason=missing_api_key")
        logger.info(
            "threat_intel_lookup",
            extra={"ip": ip, "status": "unavailable", "score": 0, "cache_hit": False},
        )
        return result

    client = AbuseIpDbClient(
        api_key=settings.ABUSEIPDB_API_KEY,
        base_url=settings.ABUSEIPDB_BASE_URL,
        timeout_seconds=settings.ABUSEIPDB_TIMEOUT_SECONDS,
        retries=settings.ABUSEIPDB_RETRIES,
    )

    try:
        payload = client.check_ip(ip, max_age, verbose)
    except AbuseIpDbUnavailable as exc:
        result = _base_result(ip)
        result.update(
            {
                "status": "unavailable",
                "found": False,
                "reputation": "unknown",
                "confidence": 0.0,
            }
        )
        result["evidence"].append(f"reason={exc.reason}")
        logger.info(
            "threat_intel_lookup",
            extra={"ip": ip, "status": "unavailable", "score": 0, "cache_hit": False},
        )
        return result
    except AbuseIpDbError as exc:
        result = _base_result(ip)
        result.update(
            {
                "status": "error",
                "found": False,
                "reputation": "unknown",
                "confidence": 0.0,
            }
        )
        result["evidence"].append(f"error={exc}")
        logger.info(
            "threat_intel_lookup",
            extra={"ip": ip, "status": "error", "score": 0, "cache_hit": False},
        )
        return result

    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    score = int(data.get("abuseConfidenceScore") or 0)
    total_reports = int(data.get("totalReports") or 0)
    distinct_reporters = int(data.get("numDistinctUsers") or data.get("distinctReporters") or 0)
    last_reported_at = data.get("lastReportedAt") or None
    is_whitelisted = bool(data.get("isWhitelisted") or False)

    result = _base_result(ip)
    result.update(
        {
            "status": "ok",
            "found": True,
            "abuse_confidence_score": score,
            "total_reports": total_reports,
            "distinct_reporters": distinct_reporters,
            "last_reported_at": last_reported_at,
            "is_whitelisted": is_whitelisted,
        }
    )

    if score >= 80:
        result["reputation"] = "malicious"
        result["confidence"] = 0.9
    elif score >= 40:
        result["reputation"] = "suspicious"
        result["confidence"] = 0.7
    elif score >= 1:
        result["reputation"] = "unknown"
        result["confidence"] = 0.4
    else:
        result["reputation"] = "unknown"
        result["confidence"] = 0.0

    if is_whitelisted:
        result["evidence"].append("whitelisted=true")
        if score < 90:
            result["reputation"] = "benign"
            result["confidence"] = min(result["confidence"], 0.3)

    evidence_summary = f"score={score} reports={total_reports} distinct={distinct_reporters}"
    if last_reported_at:
        evidence_summary += f" last={last_reported_at}"
    result["evidence"].append(evidence_summary)

    usage_type = data.get("usageType")
    country_code = data.get("countryCode")
    isp = data.get("isp")
    domain = data.get("domain")
    hostnames = data.get("hostnames") or []

    result["context"] = {
        "country_code": country_code,
        "usage_type": usage_type,
        "isp": isp,
        "domain": domain,
        "hostnames": hostnames,
    }

    context_evidence_parts = []
    if usage_type:
        context_evidence_parts.append(f"usageType={usage_type}")
    if country_code:
        context_evidence_parts.append(f"country={country_code}")
    if isp:
        context_evidence_parts.append(f"isp={isp}")
    if context_evidence_parts:
        result["evidence"].append(" ".join(context_evidence_parts))

    if verbose and hostnames:
        result["evidence"].append(f"hostnames={','.join(hostnames[:3])}")

    if verbose or settings.DEBUG:
        result["raw"] = payload

    _cache_set(cache_key, result, settings.ABUSEIPDB_CACHE_TTL_SECONDS)

    logger.info(
        "threat_intel_lookup",
        extra={
            "ip": ip,
            "status": result.get("status"),
            "score": score,
            "cache_hit": False,
        },
    )
    return result
