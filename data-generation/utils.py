from typing import List
from datetime import datetime, timedelta, timezone
import random


def datetime_to_iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def nginx_time(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def ufw_time(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")

def rand_public_ip(rng: random.Random) -> str:
    while True:
        a = rng.randint(11, 223)
        b = rng.randint(0, 255)
        c = rng.randint(0, 255)
        d = rng.randint(1, 254)
        if a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254):
            continue
        if a >= 224:
            continue
        return f"{a}.{b}.{c}.{d}"


def weighted_choice(rng: random.Random, items: List[str], weights: List[float]) -> str:
    x = rng.random() * sum(weights)
    acc = 0.0
    for item, w in zip(items, weights):
        acc += w
        if x <= acc:
            return item
    return items[-1]


def random_dt_in_window(rng: random.Random, start: datetime, end: datetime) -> datetime:
    delta_ms = (end - start).total_seconds() * 1000
    offset_ms = rng.random() * delta_ms
    return start + timedelta(milliseconds=offset_ms)
