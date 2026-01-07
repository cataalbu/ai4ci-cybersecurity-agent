# Backend Threat Intel (AbuseIPDB)

Required env vars:
- `ABUSEIPDB_API_KEY` (required to enable)
- `ABUSEIPDB_BASE_URL` (default `https://api.abuseipdb.com/api/v2`)
- `ABUSEIPDB_MAX_AGE_DAYS` (default `90`)
- `ABUSEIPDB_TIMEOUT_SECONDS` (default `5`)
- `ABUSEIPDB_CACHE_TTL_SECONDS` (default `86400`)
- `ABUSEIPDB_RETRIES` (default `2`)

Example:
```
curl "http://localhost:8000/api/threat-intel/ip/8.8.8.8?max_age_days=30&verbose=true"
```
