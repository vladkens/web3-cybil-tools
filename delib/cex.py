import hashlib
import hmac
import json
import os
import time

import httpx
from loguru import logger


def _bybit_post(url: str, pld: dict, recv_window=5000):
    access_key, secret_key = os.getenv("BYBIT_ACCESS"), os.getenv("BYBIT_SECRET")
    assert access_key and secret_key, "Bybit API keys not set in environment variables"

    uts = int(time.time() * 1000)
    pld = {**pld, "timestamp": str(uts)}

    msg = json.dumps(pld, separators=(",", ":"))
    msg = f"{uts}{access_key}{recv_window}{msg}"
    sig = hmac.new(secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()

    hdr = {
        "X-BAPI-API-KEY": access_key,
        "X-BAPI-TIMESTAMP": str(uts),
        "X-BAPI-RECV-WINDOW": str(recv_window),
        "X-BAPI-SIGN": sig,
        "Content-Type": "application/json",
    }

    rep = httpx.post(url, headers=hdr, json=pld)
    logger.debug(f">> {rep.status_code} {rep.text}")
    rep.raise_for_status()
    return rep


# https://bybit-exchange.github.io/docs/v5/asset/withdraw
def bybit_withdraw(*, chain: str, coin: str, addr: str, amount: float):
    rep = _bybit_post(
        "https://api.bybit.com/v5/asset/withdraw/create",
        {
            "coin": coin.upper(),
            "chain": chain.upper(),
            "address": str(addr).lower(),
            "amount": str(amount),
            "accountType": "FUND",
            "forceChain": 0,
        },
    )
    res = rep.json()
    assert res["retCode"] == 0, f"Withdraw failed: {res}"
    return res
