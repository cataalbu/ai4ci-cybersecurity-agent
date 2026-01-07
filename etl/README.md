# ETL for log normalization

Parses nginx access logs, API app logs, and UFW firewall logs into a unified schema, then writes parquet (preferred) or CSV (fallback).

## Usage

```bash
python -m etl.cli \
  --nginx ./logs/nginx_access.log \
  --api ./logs/api_app.log \
  --ufw ./logs/fw_ufw.log \
  --out ./data/events.parquet
```

Any input flag can be omitted; matching records are still emitted for the provided files.

### Programmatic use

```python
from etl import run_etl

result = run_etl(
    nginx_path="./logs/nginx_access.log",
    api_path="./logs/api_app.log",
    ufw_path="./logs/fw_ufw.log",
    out_path="./data/events.parquet",
)
print(result["output_path"], result["total_rows"])
```

## Schema (column order)

```
timestamp, source, client_ip, method, path, status, bytes_sent, referer, user_agent,
level, latency_ms, user, msg, hostname, verdict, src_ip, dst_ip, proto, spt, dpt,
raw_line, parse_ok, parse_error
```

`timestamp` is stored in UTC with timezone awareness when available. All other fields are nullable. Each record keeps `raw_line`, `parse_ok`, and `parse_error` for traceability.

## Notes

- Nginx: expects combined log format.
- API: key=value with quoted `msg`.
- UFW: syslog-style lines; current year is injected and adjusted for year rollover; timestamps assume local timezone then convert to UTC.

