
import random
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from utils import datetime_to_iso_utc, rand_public_ip, random_dt_in_window, nginx_time, ufw_time, weighted_choice

def format_nginx_line(
    dt: datetime,
    ip: str,
    method: str,
    path: str,
    status: int,
    bytes_sent: int,
    referer: str,
    ua: str,
) -> str:
    return f'{ip} - - [{nginx_time(dt)}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "{referer}" "{ua}"'


def format_api_line(
    dt: datetime,
    ip: str,
    method: str,
    path: str,
    status: int,
    latency_ms: int,
    user: str,
    msg: str,
) -> str:
    safe_msg = msg.replace('"', "'")
    return (
        f"{datetime_to_iso_utc(dt)} level=INFO ip={ip} method={method} path={path} "
        f"status={status} latency_ms={latency_ms} user={user} msg=\"{safe_msg}\""
    )


def format_ufw_line(
    dt: datetime,
    hostname: str,
    verdict: str,
    src: str,
    dst: str,
    proto: str,
    spt: int,
    dpt: int,
    flags: str = "SYN",
) -> str:
    mac = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55"
    return (
        f"{ufw_time(dt)} {hostname} kernel: [UFW {verdict}] IN=eth0 OUT= "
        f"MAC={mac} SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF "
        f"PROTO={proto} SPT={spt} DPT={dpt} WINDOW=29200 RES=0x00 {flags} URGP=0"
    )


@dataclass
class Config:
    hostname: str = "web-1"
    target_ip: str = "203.0.113.20"
    lines_per_batch: int = 8
    window_ms: int = 1000
    scenario_weights: Dict[str, float] = field(
        default_factory=lambda: {
            "healthy": 0.45,
            "port_scan": 0.2,
            "bruteforce": 0.15,
            "ddos": 0.1,
            "api_enum": 0.1,
        }
    )
    seed: Optional[int] = 7
    sleep_s: float = 0.0
    batch_interval_s: float = 10.0
    out_nginx: Optional[str] = "nginx_access_nonllm.log"
    out_api: Optional[str] = "api_app_nonllm.log"
    out_ufw: Optional[str] = "fw_ufw_nonllm.log"
    print_stdout: bool = True
    scenarios: List[str] = field(
        default_factory=lambda: ["healthy", "port_scan", "bruteforce", "ddos", "api_enum"]
    )
    bg_count: int = min(max(3, lines_per_batch // 2), lines_per_batch - 1) if lines_per_batch > 1 else 0


cfg = Config()


def base_context(rng: random.Random, start: datetime, end: datetime) -> Dict[str, List[str]]:
    client_ips = [rand_public_ip(rng) for _ in range(6)]
    paths = ["/", "/login", "/api/v1/items", "/static/app.js", "/health", "/favicon.ico", "/search?q=test"]
    methods = ["GET", "GET", "GET", "POST"]
    statuses = [200, 200, 200, 204, 301, 302, 400, 401, 404, 500]
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Linux x86_64)",
        "curl/8.4.0",
        "PostmanRuntime/7.36.1",
    ]
    referers = ["-", "https://example.com/", "https://google.com/", "-"]
    return {
        "client_ips": client_ips,
        "paths": paths,
        "methods": methods,
        "statuses": statuses,
        "uas": uas,
        "referers": referers,
        "start": datetime_to_iso_utc(start),
        "end": datetime_to_iso_utc(end),
    }


def gen_nginx_healthy(cfg: Config, rng: random.Random, start: datetime, end: datetime, ctx: Dict[str, List[str]], count: Optional[int] = None) -> List[str]:
    count = count or cfg.lines_per_batch
    lines = []
    for _ in range(count):
        dt = random_dt_in_window(rng, start, end)
        ip = rng.choice(ctx["client_ips"])
        method = rng.choice(ctx["methods"])
        path = rng.choice(ctx["paths"])
        status = rng.choice([200, 200, 200, 200, 301, 302, 400, 404, 500])
        bytes_sent = rng.randint(200, 3000)
        referer = rng.choice(ctx["referers"])
        ua = rng.choice(ctx["uas"])
        lines.append(format_nginx_line(dt, ip, method, path, status, bytes_sent, referer, ua))
    return lines


def gen_api_healthy(cfg: Config, rng: random.Random, start: datetime, end: datetime, ctx: Dict[str, List[str]], count: Optional[int] = None) -> List[str]:
    count = count or cfg.lines_per_batch
    users = ["-", "alice", "bob", "service-account"]
    msgs = ["ok", "cache hit", "auth failed", "validation error", "ok"]
    lines = []
    for _ in range(count):
        dt = random_dt_in_window(rng, start, end)
        ip = rng.choice(ctx["client_ips"])
        method = rng.choice(ctx["methods"])
        path = rng.choice(ctx["paths"])
        status = rng.choice([200, 200, 200, 200, 200, 204, 301, 400, 401, 404, 500])
        latency = rng.randint(20, 800)
        user = rng.choice(users)
        msg = rng.choice(msgs)
        lines.append(format_api_line(dt, ip, method, path, status, latency, user, msg))
    return lines


def gen_ufw_healthy(cfg: Config, rng: random.Random, start: datetime, end: datetime, ctx: Dict[str, List[str]], count: Optional[int] = None) -> List[str]:
    count = count or cfg.lines_per_batch
    src_pool = ctx.get("client_ips", []) or [rand_public_ip(rng) for _ in range(4)]
    lines = []
    for _ in range(count):
        dt = random_dt_in_window(rng, start, end)
        src = rng.choice(src_pool)
        proto = rng.choice(["TCP", "UDP", "TCP", "TCP"])
        dpt = rng.choice([80, 443, 8080, 53, 443, 80])
        spt = rng.randint(1024, 65535)
        verdict = "ALLOW" if rng.random() > 0.1 else "BLOCK"
        flags = "SYN" if proto == "TCP" else ""
        lines.append(format_ufw_line(dt, cfg.hostname, verdict, src, cfg.target_ip, proto, spt, dpt, flags))
    return lines


def sprinkle_background(rng: random.Random, primary: List[str], background: List[str], target: int) -> List[str]:
    # Adds background healthy logs to the primary logs
    bg = background[:]
    out: List[str] = []
    for ln in primary:
        out.append(ln)
        if bg:
            out.append(bg.pop())
            if bg and rng.random() < 0.4:
                out.append(bg.pop())
    while bg and len(out) < target:
        out.append(bg.pop())
    if len(out) > target:
        out = out[:target]
    while len(out) < target and primary:
        out.append(random.choice(primary))
    return out[:target]


def gen_port_scan(cfg: Config, rng: random.Random, start: datetime, end: datetime) -> Dict[str, List[str]]:
    attacker_ip = rand_public_ip(rng)
    ports = set([22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3389, 5900, 8080])
    while len(ports) < max(cfg.lines_per_batch, 30):
        ports.add(rng.randint(1, 65535))
    ports = sorted(list(ports))
    attack_count = cfg.lines_per_batch - cfg.bg_count

    attack_lines = []
    for i in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        dpt = ports[i % len(ports)]
        spt = rng.randint(10000, 65000)
        attack_lines.append(format_ufw_line(dt, cfg.hostname, "BLOCK", attacker_ip, cfg.target_ip, "TCP", spt, dpt, "SYN"))

    ctx = base_context(rng, start, end)
    bg_lines = gen_ufw_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)
    mixed = sprinkle_background(rng, attack_lines, bg_lines, cfg.lines_per_batch)
    return {"ufw": mixed}


def gen_bruteforce(cfg: Config, rng: random.Random, start: datetime, end: datetime, ctx: Dict[str, List[str]]) -> Dict[str, List[str]]:
    attacker_ip = rand_public_ip(rng)
    normal_ips = ctx.get("client_ips", [])
    attack_count = cfg.lines_per_batch - cfg.bg_count

    # nginx
    nginx_lines = []
    for i in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        ip = attacker_ip if rng.random() < 0.8 else rng.choice(normal_ips)
        method = "POST" if rng.random() < 0.8 else "GET"
        path = rng.choice(["/login", "/auth", "/api/v1/login"])
        status = 200 if i == attack_count - 1 and rng.random() < 0.3 else rng.choice([401, 401, 403, 401, 200])
        bytes_sent = rng.randint(150, 900)
        nginx_lines.append(format_nginx_line(dt, ip, method, path, status, bytes_sent, "-", "curl/8.4.0"))

    # api
    api_lines = []
    for i in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        ip = attacker_ip
        method = "POST"
        path = rng.choice(["/login", "/auth", "/api/v1/login"])
        status = 200 if i == attack_count - 1 and rng.random() < 0.3 else rng.choice([401, 401, 403, 401, 200])
        latency = rng.randint(50, 400)
        user = rng.choice(["-", "unknown", "admin", "root"])
        msg = "auth failed" if status != 200 else "login ok"
        api_lines.append(format_api_line(dt, ip, method, path, status, latency, user, msg))

    # ufw
    ssh_ports = [22, 2222, 2022] + sorted({rng.randint(2000, 6000) for _ in range(3)})
    ufw_lines = []
    for _ in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        dpt = rng.choice(ssh_ports)
        spt = rng.randint(10000, 65000)
        ufw_lines.append(format_ufw_line(dt, cfg.hostname, "BLOCK", attacker_ip, cfg.target_ip, "TCP", spt, dpt, "SYN"))

    bg_nginx = gen_nginx_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)
    bg_api = gen_api_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)
    bg_ufw = gen_ufw_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)

    return {
        "nginx": sprinkle_background(rng, nginx_lines, bg_nginx, cfg.lines_per_batch),
        "api": sprinkle_background(rng, api_lines, bg_api, cfg.lines_per_batch),
        "ufw": sprinkle_background(rng, ufw_lines, bg_ufw, cfg.lines_per_batch),
    }


def gen_ddos(cfg: Config, rng: random.Random, start: datetime, end: datetime, ctx: Dict[str, List[str]]) -> Dict[str, List[str]]:
    bot_ips = [rand_public_ip(rng) for _ in range(5)]
    paths = ["/", "/health", "/static/app.js", "/api/v1/items"]
    attack_count = cfg.lines_per_batch - cfg.bg_count

    nginx_lines = []
    for _ in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        ip = rng.choice(bot_ips)
        method = "GET"
        path = rng.choice(paths)
        status = rng.choice([200, 200, 200, 429, 503, 504])
        bytes_sent = rng.randint(100, 2000)
        nginx_lines.append(format_nginx_line(dt, ip, method, path, status, bytes_sent, "-", "masscan/1.0"))

    api_lines = []
    for _ in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        ip = rng.choice(bot_ips)
        path = rng.choice(paths)
        status = rng.choice([200, 200, 429, 503])
        latency = rng.randint(200, 1200)
        msg = rng.choice(["ok", "rate limited", "overload", "queue full"])
        api_lines.append(format_api_line(dt, ip, "GET", path, status, latency, "-", msg))

    ufw_lines = []
    for _ in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        ip = rng.choice(bot_ips)
        dpt = rng.choice([80, 443, 8080])
        verdict = "BLOCK" if rng.random() < 0.5 else "ALLOW"
        proto = rng.choice(["TCP", "UDP", "TCP"])
        spt = rng.randint(10000, 65000)
        flags = "SYN" if proto == "TCP" else ""
        ufw_lines.append(format_ufw_line(dt, cfg.hostname, verdict, ip, cfg.target_ip, proto, spt, dpt, flags))

    bg_nginx = gen_nginx_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)
    bg_api = gen_api_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)
    bg_ufw = gen_ufw_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)

    return {
        "nginx": sprinkle_background(rng, nginx_lines, bg_nginx, cfg.lines_per_batch),
        "api": sprinkle_background(rng, api_lines, bg_api, cfg.lines_per_batch),
        "ufw": sprinkle_background(rng, ufw_lines, bg_ufw, cfg.lines_per_batch),
    }


def gen_api_enum(cfg: Config, rng: random.Random, start: datetime, end: datetime, ctx: Dict[str, List[str]]) -> Dict[str, List[str]]:
    robot_ip = rand_public_ip(rng)
    probe_paths = [
        "/admin",
        "/debug",
        "/api/v1/secret",
        "/wp-login.php",
        "/.git/HEAD",
        "/robots.txt",
        "/config",
        "/api/v1/items",
    ]
    attack_count = cfg.lines_per_batch - cfg.bg_count

    nginx_lines = []
    for _ in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        ip = robot_ip if rng.random() < 0.8 else rng.choice(ctx["client_ips"])
        path = rng.choice(probe_paths)
        method = "GET" if rng.random() < 0.85 else "POST"
        status = rng.choice([404, 404, 401, 403, 200, 301])
        bytes_sent = rng.randint(100, 1500)
        ua = rng.choice(["Mozilla/5.0 (compatible; CensysInspect/1.1)", "sqlmap/1.7", "curl/8.4.0"])
        nginx_lines.append(format_nginx_line(dt, ip, method, path, status, bytes_sent, "-", ua))

    api_lines = []
    for _ in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        ip = robot_ip
        path = rng.choice(probe_paths)
        status = rng.choice([404, 401, 403, 200, 301])
        latency = rng.randint(30, 400)
        msg = rng.choice(["route not found", "auth required", "blocked", "ok"])
        api_lines.append(format_api_line(dt, ip, "GET", path, status, latency, "-", msg))

    ufw_lines = []
    ports = [80, 443, 8080, rng.randint(10000, 65000)]
    for _ in range(attack_count):
        dt = random_dt_in_window(rng, start, end)
        dpt = rng.choice(ports)
        verdict = "ALLOW" if rng.random() > 0.2 else "BLOCK"
        spt = rng.randint(10000, 65000)
        ufw_lines.append(format_ufw_line(dt, cfg.hostname, verdict, robot_ip, cfg.target_ip, "TCP", spt, dpt, "SYN"))

    bg_nginx = gen_nginx_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)
    bg_api = gen_api_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)
    bg_ufw = gen_ufw_healthy(cfg, rng, start, end, ctx, count=cfg.bg_count)

    return {
        "nginx": sprinkle_background(rng, nginx_lines, bg_nginx, cfg.lines_per_batch),
        "api": sprinkle_background(rng, api_lines, bg_api, cfg.lines_per_batch),
        "ufw": sprinkle_background(rng, ufw_lines, bg_ufw, cfg.lines_per_batch),
    }


def append_lines(out_file: Optional[str], lines: List[str]) -> None:
    if not out_file:
        return
    with open(out_file, "a", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")


def print_lines(label: str, lines: List[str]) -> None:
    print(f"# {label}")
    for ln in lines:
        print(ln)
    sys.stdout.flush()


def regex_match_lines(lines: List[str], pattern: re.Pattern[str]) -> bool:
    return all(pattern.match(ln) for ln in lines)


def validate_outputs(outputs: Dict[str, List[str]], expected: int) -> List[str]:
    errors: List[str] = []
    nginx_pat = re.compile(r'.+"[A-Z]+ .+ HTTP/.+" \d{3} \d+ .+')
    api_pat = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z level=INFO .*")
    ufw_pat = re.compile(r"[A-Z][a-z]{2} \d{1,2} .*\[UFW (BLOCK|ALLOW)\].*SRC=.*DST=.*PROTO=.*DPT=.*")

    for name, lines in outputs.items():
        if len(lines) != expected:
            errors.append(f"{name}: line-count {len(lines)} != {expected}")
            continue
        if name == "nginx" and not regex_match_lines(lines, nginx_pat):
            errors.append("nginx: regex check failed")
        if name == "api" and not regex_match_lines(lines, api_pat):
            errors.append("api: regex check failed")
        if name == "ufw" and not regex_match_lines(lines, ufw_pat):
            errors.append("ufw: regex check failed")
    return errors


def generate_batch(cfg: Config, rng: random.Random, sim_t: datetime) -> Tuple[Dict[str, List[str]], datetime, List[str]]:
    start = sim_t
    end = start + timedelta(milliseconds=cfg.window_ms)
    ctx = base_context(rng, start, end)

    weights = [cfg.scenario_weights.get(name, 1.0) for name in cfg.scenarios]
    if sum(weights) <= 0:
        weights = [1.0 for _ in cfg.scenarios]
    scenario = weighted_choice(rng, cfg.scenarios, weights)

    outputs: Dict[str, List[str]] = {}
    if scenario == "healthy":
        outputs["nginx"] = gen_nginx_healthy(cfg, rng, start, end, ctx)
        outputs["api"] = gen_api_healthy(cfg, rng, start, end, ctx)
        outputs["ufw"] = gen_ufw_healthy(cfg, rng, start, end, ctx)
    elif scenario == "port_scan":
        outputs.update(gen_port_scan(cfg, rng, start, end))
    elif scenario == "bruteforce":
        outputs.update(gen_bruteforce(cfg, rng, start, end, ctx))
    elif scenario == "ddos":
        outputs.update(gen_ddos(cfg, rng, start, end, ctx))
    elif scenario == "api_enum":
        outputs.update(gen_api_enum(cfg, rng, start, end, ctx))

    errors = validate_outputs(outputs, cfg.lines_per_batch)
    return outputs, end, errors


def main() -> int:
    rng = random.Random(cfg.seed)
    sim_t = datetime.now(timezone.utc)

    print("# Synthetic log generator (no LLM)")
    print("# Writing logs to:")
    print(f"# - nginx: {cfg.out_nginx}")
    print(f"# - api:   {cfg.out_api}")
    print(f"# - ufw:   {cfg.out_ufw}")
    print("# Press Ctrl+C to stop.")

    try:
        while True:
            outputs, sim_t, errors = generate_batch(cfg, rng, sim_t)
            if errors:
                print(f"# Skipping batch due to errors: {errors}", file=sys.stderr)
            else:
                if cfg.print_stdout:
                    if "nginx" in outputs:
                        print_lines("nginx", outputs["nginx"])
                    if "api" in outputs:
                        print_lines("api", outputs["api"])
                    if "ufw" in outputs:
                        print_lines("ufw", outputs["ufw"])

                append_lines(cfg.out_nginx, outputs.get("nginx", []))
                append_lines(cfg.out_api, outputs.get("api", []))
                append_lines(cfg.out_ufw, outputs.get("ufw", []))

            if cfg.batch_interval_s > 0:
                time.sleep(cfg.batch_interval_s)

    except KeyboardInterrupt:
        print("\n# Stopped.", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

