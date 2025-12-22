import os
import random
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from utils import datetime_to_iso_utc, rand_public_ip
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph


@dataclass
class Config:
    model: str = "openai/gpt-oss-20b"
    base_url: str = "http://localhost:1234/v1"
    api_key: str = os.getenv("OPENAI_API_KEY", "lm-studio")
    hostname: str = "web-1"
    target_ip: str = "203.0.113.20"
    lines_per_batch: int = 10
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
    temperature: float = 0.2
    sleep_s: float = 0.0
    out_nginx: Optional[str] = "nginx_access.log"
    out_api: Optional[str] = "api_app.log"
    out_ufw: Optional[str] = "fw_ufw.log"
    scenarios: List[str] = field(
        default_factory=lambda: ["healthy", "port_scan", "bruteforce", "ddos", "api_enum"]
    )


cfg = Config()

NGINX_FORMAT_SPEC = (
    'Nginx "combined" access log format:\n'
    '  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent"\n'
    "Example:\n"
    '  203.0.113.9 - - [17/Dec/2025:12:00:00 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"\n'
)

API_FORMAT_SPEC = (
    "Backend app log format (plain text, one line per request):\n"
    "  <iso8601_z> level=INFO ip=... method=... path=... status=... latency_ms=... user=... msg=\"...\"\n"
    "Example:\n"
    '  2025-12-17T12:00:00.123Z level=INFO ip=203.0.113.9 method=GET path=/api/v1/items status=200 latency_ms=123 user=alice msg="ok"\n'
)

UFW_FORMAT_SPEC = (
    "Linux UFW/iptables-like firewall log format (single line per blocked inbound attempt).\n"
    "Example:\n"
    "  Dec 17 12:00:00 host kernel: [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:..."
    " SRC=198.51.100.10 DST=203.0.113.20 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=12345 DF "
    "PROTO=TCP SPT=51515 DPT=22 WINDOW=29200 RES=0x00 SYN URGP=0\n"
)


def build_context(rng: random.Random, start: datetime, end: datetime) -> Dict[str, List[str]]:
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
        "statuses": [str(x) for x in statuses],
        "uas": uas,
        "referers": referers,
        "start": datetime_to_iso_utc(start),
        "end": datetime_to_iso_utc(end),
    }


def build_prompt_nginx(cfg: Config, ctx: Dict[str, List[str]]) -> str:
    return f"""
You generate realistic nginx access logs.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{NGINX_FORMAT_SPEC}

Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Each line MUST be a valid nginx combined log line matching the format above.
- Time window: [{ctx['start']} , {ctx['end']}] (UTC +0000).
- Keep IPs, methods, paths, statuses plausible and consistent.
- Use the provided building blocks to correlate traffic with the app:
  - Client IPs: {", ".join(ctx["client_ips"])}
  - Methods: {", ".join(ctx["methods"])}
  - Paths: {", ".join(ctx["paths"])}
  - Statuses (sample): {", ".join(ctx["statuses"])}
  - User-Agents (sample): {", ".join(ctx["uas"])}
  - Referers (sample): {", ".join(ctx["referers"])}
- Include a small amount of 4xx/5xx but mostly healthy traffic.

Now output the {cfg.lines_per_batch} log lines:
""".strip()


def build_prompt_api(cfg: Config, ctx: Dict[str, List[str]]) -> str:
    return f"""
You generate realistic backend application logs correlated with nginx access logs.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{API_FORMAT_SPEC}

Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Time window: [{ctx['start']} , {ctx['end']}].
- Each line should reflect the same kinds of requests seen in nginx: reuse paths, methods, IPs, and similar statuses.
- Mix successful (2xx) and minor failures (4xx/5xx) but stay mostly healthy.
- latency_ms should be plausible (20-800ms) and align with path complexity.
- user can be "-", "alice", "bob", "service-account", or similar.
- msg should be short human-readable notes like "ok", "cache hit", "auth failed", "validation error".

Now output the {cfg.lines_per_batch} log lines:
""".strip()


def build_prompt_ufw_port_scan(cfg: Config, rng: random.Random, start: datetime, end: datetime) -> str:
    attacker_ip = rand_public_ip(rng)
    common_ports = [22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3389, 5900, 8080]
    ports = set(common_ports)
    while len(ports) < min(cfg.lines_per_batch, 60):
        ports.add(rng.randint(1, 65535))
    ports = sorted(list(ports))[: max(10, min(cfg.lines_per_batch, 60))]

    return f"""
You generate realistic firewall logs for a port scan.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{UFW_FORMAT_SPEC}

Scenario: PORT SCAN against the server.
Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Each line MUST be a valid UFW/iptables-style firewall block log line.
- Hostname: {cfg.hostname}
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}] (UTC).
- Timestamps must be syslog style like "Dec 17 12:00:00".
- Attacker SRC must be CONSTANT across the batch: SRC={attacker_ip}
- Target must be CONSTANT across the batch: DST={cfg.target_ip}
- PROTO should be mostly TCP with SYN set, and a few UDP probes are allowed.
- DPT must vary widely (port scan behavior). Use these many times, but feel free to add more: {", ".join(map(str, ports))}.

Now output the {cfg.lines_per_batch} firewall log lines:
""".strip()


def build_prompt_ufw_normal(cfg: Config, rng: random.Random, start: datetime, end: datetime, ctx: Dict[str, List[str]]) -> str:
    src_pool = ctx.get("client_ips", [])
    if not src_pool:
        src_pool = [rand_public_ip(rng) for _ in range(4)]

    return f"""
You generate realistic firewall logs for normal healthy traffic.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{UFW_FORMAT_SPEC}

Scenario: HEALTHY traffic (mostly allowed), occasional harmless noise.
Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Hostname: {cfg.hostname}
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}] (UTC).
- Use SRC addresses drawn from: {", ".join(src_pool)}
- DST must be {cfg.target_ip} for inbound entries.
- Majority of lines should be "[UFW ALLOW]" for expected inbound web ports (80, 443, 8080) or outbound DNS/HTTPS.
- Include 1-2 "[UFW BLOCK]" noise entries (e.g., unexpected ports or UDP probe) but keep overall tone healthy.
- For outbound DNS/HTTPS you may flip IN/OUT accordingly, but keep SRC/DST realistic.
- Every line MUST include SRC, DST, PROTO, SPT, DPT and reasonable flags (e.g., SYN for TCP).

Now output the {cfg.lines_per_batch} firewall log lines:
""".strip()


def build_prompt_nginx_bruteforce(cfg: Config, ctx: Dict[str, List[str]], start: datetime, end: datetime, attacker_ip: str) -> str:
    return f"""
You generate nginx access logs for a brute-force login attempt.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{NGINX_FORMAT_SPEC}

Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}] (UTC +0000).
- Attacker IP must dominate: {attacker_ip}; mix in a few normal IPs from: {", ".join(ctx.get("client_ips", []))}
- Paths should target login endpoints (/login, /auth, /api/v1/login) with many 401/403 and a few 200 after retries.
- Methods mostly POST (some GET).
- User-Agent can resemble curl/bots; include Referer "-".
- Keep combined format valid.

Now output the {cfg.lines_per_batch} log lines:
""".strip()


def build_prompt_api_bruteforce(cfg: Config, ctx: Dict[str, List[str]], start: datetime, end: datetime, attacker_ip: str) -> str:
    return f"""
You generate backend application logs correlated to brute-force login attempts.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{API_FORMAT_SPEC}

Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}].
- Most lines should be 401/403 login failures from ip={attacker_ip}, few 200 when captcha/rate-limit passes.
- Paths: /login, /auth, /api/v1/login; methods POST with latency_ms 50-400.
- user can be "-", "unknown", or guessed usernames; msg like "auth failed", "rate limited", "password invalid".

Now output the {cfg.lines_per_batch} log lines:
""".strip()


def build_prompt_ufw_bruteforce(cfg: Config, rng: random.Random, start: datetime, end: datetime, attacker_ip: str) -> str:
    ssh_ports = [22, 2222, 2022]
    extra = sorted({rng.randint(2000, 6000) for _ in range(3)})
    ports = ssh_ports + extra
    return f"""
You generate firewall logs for SSH brute-force.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{UFW_FORMAT_SPEC}

Scenario: BRUTE FORCE against SSH.
Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Hostname: {cfg.hostname}
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}] (UTC).
- SRC must be CONSTANT: SRC={attacker_ip}
- DST must be CONSTANT: DST={cfg.target_ip}
- Mostly TCP SYN to DPT in {", ".join(map(str, ports))}; all BLOCK.
- SPT can vary in a small range to mimic retries.

Now output the {cfg.lines_per_batch} firewall log lines:
""".strip()


def build_prompt_nginx_ddos(cfg: Config, ctx: Dict[str, List[str]], start: datetime, end: datetime, bot_ips: List[str]) -> str:
    return f"""
You generate nginx access logs for a web DDoS burst.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{NGINX_FORMAT_SPEC}

Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}] (UTC +0000).
- Use many repeated requests from bot IPs: {", ".join(bot_ips)} hitting "/" "/health" "/static" "/api/v1/items".
- Include elevated 429/503/504 plus some 200s.
- Methods mostly GET; keep combined format valid; Referer "-" or empty.

Now output the {cfg.lines_per_batch} log lines:
""".strip()


def build_prompt_api_ddos(cfg: Config, ctx: Dict[str, List[str]], start: datetime, end: datetime, bot_ips: List[str]) -> str:
    return f"""
You generate backend application logs correlated to a DDoS burst.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{API_FORMAT_SPEC}

Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}].
- IPs should be from: {", ".join(bot_ips)} with many rapid repeats.
- Paths: "/", "/health", "/api/v1/items", "/static/app.js".
- Mix 200 with 429/503; latency_ms can spike (200-1200ms).
- msg like "ok", "rate limited", "overload", "queue full".

Now output the {cfg.lines_per_batch} log lines:
""".strip()


def build_prompt_ufw_ddos(cfg: Config, rng: random.Random, start: datetime, end: datetime, bot_ips: List[str]) -> str:
    return f"""
You generate firewall logs for DDoS mitigation.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{UFW_FORMAT_SPEC}

Scenario: DDoS mitigation on web ports.
Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Hostname: {cfg.hostname}
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}] (UTC).
- Use SRC drawn from: {", ".join(bot_ips)}
- DST must be {cfg.target_ip}
- Mix BLOCK and ALLOW on PROTO=TCP to DPT=80/443/8080, some UDP noise allowed.
- Keep SPT varied; include SYN for TCP.

Now output the {cfg.lines_per_batch} firewall log lines:
""".strip()


def build_prompt_nginx_api_enum(cfg: Config, ctx: Dict[str, List[str]], start: datetime, end: datetime, robot_ip: str) -> str:
    return f"""
You generate nginx access logs for API enumeration by a robot.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{NGINX_FORMAT_SPEC}

Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}] (UTC +0000).
- Majority of requests from robot IP {robot_ip}; few normal hits from ctx IPs allowed.
- Paths should probe many endpoints (/admin, /debug, /api/v1/secret, /wp-login.php, /.git/HEAD, /robots.txt, /config).
- Status mix: mostly 404/401/403 with some 200/301.
- Methods GET and a few POST; Referer "-"; User-Agent looks like a scanner/bot.

Now output the {cfg.lines_per_batch} log lines:
""".strip()


def build_prompt_api_api_enum(cfg: Config, ctx: Dict[str, List[str]], start: datetime, end: datetime, robot_ip: str) -> str:
    return f"""
You generate backend application logs for API enumeration attempts.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{API_FORMAT_SPEC}

Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}].
- Requests mainly from ip={robot_ip} probing uncommon paths; include 404/401/403, some 200/301.
- Methods: GET with occasional POST; latency_ms 30-400.
- user mostly "-" ; msg like "route not found", "auth required", "blocked", "ok".

Now output the {cfg.lines_per_batch} log lines:
""".strip()


def build_prompt_ufw_api_enum(cfg: Config, rng: random.Random, start: datetime, end: datetime, robot_ip: str) -> str:
    ports = [80, 443, 8080, rng.randint(10000, 65000)]
    return f"""
You generate firewall logs during API enumeration probing.
Output ONLY raw log lines, no code fences, no explanations, no JSON.

{UFW_FORMAT_SPEC}

Scenario: robot probing APIs.
Constraints:
- Produce EXACTLY {cfg.lines_per_batch} lines.
- Hostname: {cfg.hostname}
- Time window: [{datetime_to_iso_utc(start)} , {datetime_to_iso_utc(end)}] (UTC).
- SRC should be {robot_ip}; DST {cfg.target_ip}; PROTO mostly TCP.
- Mostly ALLOW to DPT {", ".join(map(str, ports))} with 1-2 BLOCK entries for odd ports or UDP probes.
- Keep format valid with SRC/DST/PROTO/SPT/DPT present.

Now output the {cfg.lines_per_batch} firewall log lines:
""".strip()


# ----------------------------
# LLM + output handling
# ----------------------------

def llm_generate_lines(llm: ChatOpenAI, prompt: str) -> List[str]:
    msg = llm.invoke(
        [
            SystemMessage(content="You are a log generator. Output only log lines, nothing else."),
            HumanMessage(content=prompt),
        ]
    )
    text = (msg.content or "").strip()
    lines = [ln.rstrip("\n") for ln in text.splitlines() if ln.strip() != ""]
    return lines


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



def build_graph(llm: ChatOpenAI, rng: random.Random):
    graph = StateGraph(dict)

    def select_scenario(state: dict) -> dict:
        weights = [cfg.scenario_weights.get(name, 1.0) for name in cfg.scenarios]
        if sum(weights) <= 0:
            weights = [1.0 for _ in cfg.scenarios]
        scenario = weighted_choice(rng, cfg.scenarios, weights)
        start = state["sim_t"]
        end = start + timedelta(milliseconds=cfg.window_ms)
        ctx = build_context(rng, start, end)
        return {**state, "scenario": scenario, "start": start, "end": end, "context": ctx}

    def build_prompts(state: dict) -> dict:
        scenario = state["scenario"]
        prompts: Dict[str, str] = {}
        if scenario == "healthy":
            prompts["nginx"] = build_prompt_nginx(cfg, state["context"])
            prompts["api"] = build_prompt_api(cfg, state["context"])
            prompts["ufw"] = build_prompt_ufw_normal(cfg, rng, state["start"], state["end"], state["context"])
        elif scenario == "port_scan":
            prompts["ufw"] = build_prompt_ufw_port_scan(cfg, rng, state["start"], state["end"])
        elif scenario == "bruteforce":
            attacker_ip = rand_public_ip(rng)
            prompts["nginx"] = build_prompt_nginx_bruteforce(cfg, state["context"], state["start"], state["end"], attacker_ip)
            prompts["api"] = build_prompt_api_bruteforce(cfg, state["context"], state["start"], state["end"], attacker_ip)
            prompts["ufw"] = build_prompt_ufw_bruteforce(cfg, rng, state["start"], state["end"], attacker_ip)
        elif scenario == "ddos":
            bot_ips = [rand_public_ip(rng) for _ in range(5)]
            prompts["nginx"] = build_prompt_nginx_ddos(cfg, state["context"], state["start"], state["end"], bot_ips)
            prompts["api"] = build_prompt_api_ddos(cfg, state["context"], state["start"], state["end"], bot_ips)
            prompts["ufw"] = build_prompt_ufw_ddos(cfg, rng, state["start"], state["end"], bot_ips)
        elif scenario == "api_enum":
            robot_ip = rand_public_ip(rng)
            prompts["nginx"] = build_prompt_nginx_api_enum(cfg, state["context"], state["start"], state["end"], robot_ip)
            prompts["api"] = build_prompt_api_api_enum(cfg, state["context"], state["start"], state["end"], robot_ip)
            prompts["ufw"] = build_prompt_ufw_api_enum(cfg, rng, state["start"], state["end"], robot_ip)
        return {**state, "prompts": prompts}

    def generate(state: dict) -> dict:
        outputs: Dict[str, List[str]] = {}
        errors: List[str] = []
        for name, prompt in state.get("prompts", {}).items():
            try:
                outputs[name] = llm_generate_lines(llm, prompt)
            except Exception as exc:  # pragma: no cover - runtime safety
                errors.append(f"{name}: LLM error {exc}")

        return {**state, "outputs": outputs, "errors": errors}

    def validate(state: dict) -> dict:
        errors = list(state.get("errors", []))
        outputs = state.get("outputs", {})
        expected = cfg.lines_per_batch

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

        return {**state, "errors": errors}

    def write_logs(state: dict) -> dict:
        errors: List[str] = state.get("errors", [])
        outputs: Dict[str, List[str]] = state.get("outputs", {})

        if errors:
            print(f"# Skipping batch due to errors: {errors}", file=sys.stderr)
            return state

        append_lines(cfg.out_nginx, outputs.get("nginx", []))
        append_lines(cfg.out_api, outputs.get("api", []))
        append_lines(cfg.out_ufw, outputs.get("ufw", []))
        return state

    graph.add_node("select", select_scenario)
    graph.add_node("prompts", build_prompts)
    graph.add_node("generate", generate)
    graph.add_node("validate", validate)
    graph.add_node("write", write_logs)

    graph.set_entry_point("select")
    graph.add_edge("select", "prompts")
    graph.add_edge("prompts", "generate")
    graph.add_edge("generate", "validate")
    graph.add_edge("validate", "write")
    graph.add_edge("write", END)

    return graph.compile()


def main() -> int:
    rng = random.Random(cfg.seed)

    llm = ChatOpenAI(
        model=cfg.model,
        base_url=cfg.base_url,
        api_key=cfg.api_key,
        temperature=cfg.temperature,
    )

    app = build_graph(llm, rng)

    sim_t = datetime.now(timezone.utc)
    print(f"# Starting (model={cfg.model}, base_url={cfg.base_url})")
    print("# Writing logs to:")
    print(f"# - nginx: {cfg.out_nginx}")
    print(f"# - api:   {cfg.out_api}")
    print(f"# - ufw:   {cfg.out_ufw}")
    print("# Press Ctrl+C to stop.")

    try:
        while True:
            state = {"sim_t": sim_t}
            result = app.invoke(state)
            sim_t = result.get("end", sim_t + timedelta(milliseconds=cfg.window_ms))
            if cfg.sleep_s > 0:
                time.sleep(cfg.sleep_s)
    except KeyboardInterrupt:
        print("\n# Stopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
