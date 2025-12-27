import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import TypedDict

import httpx
from loguru import logger

from .utils import first


@dataclass
class Balance:
    where: str
    coin: str
    amount: float
    amount_usd: float | None = None


class BybitWithdrawable(TypedDict):
    withdrawable: float
    total: float
    can_all: bool


def _bybit_call(method: str, url: str, pld: dict | None, recv_window=5000):
    method = method.upper()
    assert method in ("POST", "GET"), f"Unsupported method: {method}"

    access_key, secret_key = os.getenv("BYBIT_ACCESS"), os.getenv("BYBIT_SECRET")
    assert access_key and secret_key, "Bybit API keys not set in environment variables"

    uts = int(time.time() * 1000)
    pld = pld or {}

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


# https://bybit-exchange.github.io/docs/v5/asset/balance/delay-amount
def bybit_withdrawable(coin: str) -> BybitWithdrawable:
    url = "/v5/asset/withdraw/withdrawable-amount"
    res = _bybit_call("GET", url, {"coin": coin.upper()})

    res = res["result"]["withdrawableAmount"]["FUND"]
    assert res["coin"] == coin.upper(), f"Unexpected coin in response: {res}"
    amount1 = float(res["withdrawableAmount"])
    amount2 = float(res["availableBalance"])

    can_all = amount1 >= amount2
    return BybitWithdrawable(withdrawable=amount1, total=amount2, can_all=can_all)


def bybit_wait_deposit(coin: str, wait_sec=60) -> float:
    stime = time.time()
    while True:
        res = bybit_withdrawable(coin)

        dtime = time.time() - stime
        msg = " ".join(f"{k}={v}" for k, v in res.items())
        msg = f"{coin}: {msg} (after {dtime:.0f}s)"

        if res["can_all"]:
            logger.debug(msg + " – can withdraw all!")
            return res["withdrawable"]

        logger.debug(msg + f" – not ready, waiting {wait_sec}s...")
        time.sleep(wait_sec)


# https://www.mexc.com/api-docs/spot-v3/general-info
def _mexc_call(method: str, url: str, pld: dict | None, recv_window=5000):
    method = method.upper()
    assert method in ("POST", "GET"), f"Unsupported method: {method}"

    access_key, secret_key = os.getenv("MEXC_ACCESS"), os.getenv("MEXC_SECRET")
    assert access_key and secret_key, "Mexc API keys not set in environment variables"

    uts = int(time.time() * 1000)
    pld = {**(pld or {}), "timestamp": str(uts)}

    msg = "&".join([f"{k}={v}" for k, v in pld.items()])
    sig = hmac.new(secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()

    pld = {**pld, "signature": sig}
    rep = httpx.request(
        method,
        "https://api.mexc.com" + url,
        headers={"X-MEXC-APIKEY": access_key, "content-type": "application/json"},
        params=pld,
    )

    logger.debug(f">> {rep.status_code} {rep.text}") if rep.status_code >= 400 else None
    rep.raise_for_status()
    return rep.json()


# https://www.mexc.com/api-docs/spot-v3/spot-account-trade#account-information
def mexc_spot() -> list[Balance]:
    url = "/api/v3/account"
    res = _mexc_call("GET", url, None)
    return res["balances"]  # .asset, .free, .locked, .available


@lru_cache(maxsize=1)
def mexc_networks():
    # https://www.mexc.com/api-docs/spot-v3/wallet-endpoints#query-the-currency-information
    url = "/api/v3/capital/config/getall"
    return _mexc_call("GET", url, None)


# https://www.mexc.com/api-docs/spot-v3/wallet-endpoints#withdrawnew
def mexc_withdraw(*, chain: str, coin: str, addr: str, amount: float):
    chain, coin = chain.upper(), coin.upper()

    config = first([x for x in mexc_networks() if x["coin"] == coin])
    assert config, f"Coin {coin} not found in Mexc networks"

    config = first([x for x in config["networkList"] if x["netWork"] == chain])
    assert config, f"Chain {chain} not found for coin {coin} in Mexc networks"

    min_amount, max_amount = float(config["withdrawMin"]), float(config["withdrawMax"])
    assert config["withdrawEnable"], f"Withdraw not enabled for {coin} on {chain}"
    assert min_amount <= amount <= max_amount, (
        f"Amount {amount} out of range [{min_amount}, {max_amount}] for {coin} on {chain}"
    )

    pld = {
        "coin": coin,
        "address": str(addr).lower(),
        "amount": str(amount),
        "netWork": chain,
    }

    if config.get("contract"):
        pld["contractAddress"] = config["contract"]

    res = _mexc_call("POST", "/api/v3/capital/withdraw", pld)
    logger.debug(f"Mexc withdraw response: {res}")
    return res
