import json
import os
import random
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import TypeVar

import httpx
from fake_useragent import UserAgent

from .filecache import sqlcache

T = TypeVar("T")


def first(items: list[T]) -> T | None:
    return items[0] if items else None


def fake_ua() -> str:
    return UserAgent(platforms=["desktop"], os=["Mac OS X"]).random


def load_lines(filepath: str) -> list[str]:
    with open(filepath, "r") as fp:
        lines = [x.strip() for x in fp.readlines()]
        lines = [x for x in lines if x and not x.startswith("#")]
        return lines


def parse_proxy(proxy: str | None) -> str | None:
    if not proxy:
        return None

    if not proxy.startswith("http") and proxy.count(":") == 3:
        parts = proxy.split(":")
        proxy = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        return proxy

    return proxy


def check_ip(proxy: str | None = None):
    proxy = parse_proxy(proxy)
    rep = httpx.get("https://ipapi.co/json/", proxy=proxy, timeout=10)
    rep.raise_for_status()
    dat = rep.json()

    ip = dat.get("ip")
    country = dat.get("country_name", "Unknown")
    country_code = dat.get("country_code", "XX")
    return {"ip": ip, "country_code": country_code.lower(), "country": country}


@sqlcache(ttl="60m")
def load_proxies(filepath: str) -> list[tuple[str, dict]]:
    with open(filepath, "r") as fp:
        data = fp.read()

    items = data.strip().split("\n")
    items = [x.strip() for x in items if x.strip()]
    items = list(set(items))

    def _probe(raw_proxy: str):
        try:
            info = check_ip(raw_proxy)
            return raw_proxy, info
        except Exception:
            return None

    good = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(_probe, p): p for p in items}
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                good.append(res)

    return good


def load_cex_mapping(filename: str) -> dict:
    mapping = {}
    for line in load_lines(filename):
        eth_addr, cex_addr, *rest = line.split()
        eth_addr = eth_addr.strip().lower()
        cex_addr = cex_addr.strip().lower()
        # cex_name = rest[0].strip().lower() if rest else ""
        mapping[eth_addr] = cex_addr

    return mapping


def cmd_say(msg: str, repeat=1):
    try:
        msg = msg.replace('"', '\\"')
        for _ in range(repeat):
            os.system(f'say "{msg}"')
    except Exception:
        pass


@dataclass(repr=False)
class BWWallet:
    label: str
    address: str
    privkey: str

    def __repr__(self):
        return f"BWWallet({self.address} aka {self.label})"
        # return f"BWWallet(label={self.label!r}, address={self.address!r}, privkey='***hidden***')"


def get_bw_wallets(name: str) -> list[BWWallet]:
    out = subprocess.check_output(["bw", "get", "item", name], env=os.environ)
    out = json.loads(out.decode())
    assert out["name"] == name, f"Unexpected item name: {out['name']}"
    assert out["type"] == 2, f"Unexpected item type: {out['type']}"

    items = []
    for x in out["fields"]:
        if x["type"] != 1:
            continue

        parts = [x.strip() for x in x["name"].split(" - ")]
        parts = [x for x in parts if x]
        assert len(parts) == 2, f"Unexpected field name format: {x['name']}"

        item = BWWallet(parts[0].lower(), parts[1].lower(), x["value"])
        items.append(item)

    return items


class CltManager:
    _proxies: list[str] = []

    @classmethod
    def load_proxies(cls, filepath="_proxies.txt"):
        working_proxies = load_proxies(filepath)
        cls._proxies = [x[0] for x in working_proxies]

    @classmethod
    def get_proxy_txt(cls, addr: str) -> str | None:
        rnd = random.Random(addr.lower())
        proxy = rnd.choice(cls._proxies) if cls._proxies else None
        return proxy

    @classmethod
    def get_proxy(cls, addr: str) -> str | None:
        return parse_proxy(cls.get_proxy_txt(addr))

    @classmethod
    def create(cls, addr: str, headers: dict | None = None) -> httpx.Client:
        proxy = cls.get_proxy(addr)
        default_headers = {
            "user-agent": fake_ua(),
            "accept-language": "en-US,en;q=0.9",
        }

        headers = headers or {}
        headers = {k.lower(): v for k, v in headers.items()}
        headers.update(default_headers)

        return httpx.Client(headers=headers, proxy=proxy, timeout=30.0)
