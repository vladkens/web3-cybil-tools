import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass

import httpx
from loguru import logger


@dataclass
class Balance:
    where: str
    coin: str
    amount: float
    amount_usd: float | None = None


def _bybit_call(method: str, url: str, pld: dict, recv_window=5000):
    method = method.upper()
    assert method in ("POST", "GET"), f"Unsupported method: {method}"

    access_key, secret_key = os.getenv("BYBIT_ACCESS"), os.getenv("BYBIT_SECRET")
    assert access_key and secret_key, "Bybit API keys not set in environment variables"

    uts = int(time.time() * 1000)

    if method == "GET":
        msg = "&".join([f"{k}={v}" for k, v in sorted(pld.items())])

    if method == "POST":
        pld = {**pld, "timestamp": str(uts)}
        msg = json.dumps(pld, separators=(",", ":"))

    msg = f"{uts}{access_key}{recv_window}{msg}"
    sig = hmac.new(secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()

    hdr = {
        "X-BAPI-API-KEY": access_key,
        "X-BAPI-TIMESTAMP": str(uts),
        "X-BAPI-RECV-WINDOW": str(recv_window),
        "X-BAPI-SIGN": sig,
    }

    if method == "POST":
        hdr["Content-Type"] = "application/json"

    rep = httpx.request(
        method,
        "https://api.bybit.com" + url,
        headers=hdr,
        params=pld if method == "GET" else None,
        json=pld if method == "POST" else None,
    )

    # logger.debug(f">> {rep.status_code} {rep.text}")
    rep.raise_for_status()

    res = rep.json()
    assert res["retCode"] == 0, f"Bybit API error: {res}"
    return res


# https://bybit-exchange.github.io/docs/v5/asset/withdraw
def bybit_withdraw(*, chain: str, coin: str, addr: str, amount: float):
    pld = {
        "coin": coin.upper(),
        "chain": chain.upper(),
        "address": str(addr).lower(),
        "amount": str(amount),
        "accountType": "FUND",
        "forceChain": 0,
    }

    return _bybit_call("POST", "/v5/asset/withdraw/create", pld)


# https://bybit-exchange.github.io/docs/api-explorer/v5/asset/all-balance
def bybit_fund():
    url = "/v5/asset/transfer/query-account-coins-balance"
    res = _bybit_call("GET", url, {"accountType": "FUND"})

    items: list[Balance] = []
    for x in res["result"]["balance"]:
        amount = float(x["walletBalance"])
        if amount <= 0:
            continue

        items.append(Balance("bybit", x["coin"], amount))

    return items
