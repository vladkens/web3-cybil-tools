#!/usr/bin/env python3
import random
from functools import lru_cache

import httpx
from fake_useragent import UserAgent
from web3 import Web3

BASE_URL = "https://kinetiq-foundation.org"


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


@lru_cache
def get_clt(addr: str) -> httpx.Client:
    proxies = load_lines("_proxies.txt")
    proxy = random.Random(addr.lower()).choice(proxies) if proxies else None
    proxy = parse_proxy(proxy)

    ua = UserAgent(platforms=["desktop"], os=["Mac OS X"]).random
    return httpx.Client(proxy=proxy, headers={"user-agent": ua}, timeout=15.0)


def check_eligible(addr: str):
    clt = get_clt(addr)
    clt.headers.update({"origin": BASE_URL, "referer": f"{BASE_URL}/terms"})

    rep = clt.post(
        f"{BASE_URL}/terms",
        json=[{"chainId": 1, "userAddress": addr}],
        headers={"next-action": "7f6c70b3e2d3787a532e08f5259ae1e5e93a577115"},
    )
    rep.raise_for_status()
    status_line = [x.strip() for x in rep.text.splitlines()][-1]
    return status_line == "1:true"


def main():
    wallets = load_lines("_wallets.txt")
    for i, privkey in enumerate(wallets, 1):
        acc = Web3().eth.account.from_key(privkey)
        is_eligible = check_eligible(acc.address)
        print(f"{i:03d}/{len(wallets):03d} - {acc.address} - Eligible: {is_eligible}")


if __name__ == "__main__":
    main()
