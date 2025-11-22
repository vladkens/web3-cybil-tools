import json
import os
import random
import time
from datetime import UTC, datetime
from decimal import ROUND_DOWN, Decimal
from functools import lru_cache

import httpx
import requests
import web3.exceptions
from eth_account.signers.local import LocalAccount
from eth_utils.currency import to_wei
from hyperliquid.exchange import Exchange
from loguru import logger
from web3 import Web3

from delib import CltManager, Erc20, Erc4626, evm_call, to_addr
from delib.cex import bybit_withdraw
from delib.dex import Hyperliquid, HyperUnit, Hypurr, Valantis
from delib.utils import cmd_say, load_cex_mapping


class WrkCfg:
    hl_max_dep: int | None = None  # max USDC deposit to HL; None = all wallet balance
    max_retries = 5  # max retries on action failure
    fail_fast_on_unknown_err = False  # stop worker on unknown error or try again
    cex_withdraw = True  # try to withdraw from CEX (only Bybit supported right now)
    cex_withdraw_amount = 500  # USDC amount to withdraw from CEX


ETH_RPC_URL = "https://1rpc.io/eth"
HLE_RPC_URL = "https://rpc.hyperliquid.xyz/evm"
ARB_RPC_URL = "https://arb1.arbitrum.io/rpc"

HL_API_URL = "https://api.hyperliquid.xyz"
HL_BRIDGE_ADDR = "0x2df1c51e09aecf9cacb7bc98cb1742757f163df7"

NUL_ADDR = "0x0000000000000000000000000000000000000000"
ARB_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"

HL_DEX_HYPE = "HYPE:0x0d01dc56dcaaca66ad901c959b4011ec"
HL_DEX_USDC = "USDC:0x6d1e7cde53ba9467b783cb7c530ce054"
HL_DEX_USDE = "USDE:0x2e6d84f2d7ca82e6581e03523e4389f7"
HL_DEX_UETH = "UETH:0xe1edd30daaf5caac3fe63569e24748da"

HL_EVM_USDE = "0x5d3a1ff2b6bab83b63cd9ad0787074081a52ef34"
HL_EVM_USDT = "0xb8ce59fc3717ada4c02eadf9682a9e934f625ebb"
HL_EVM_UETH = "0xbe6727b535545c67d5caa73dea54865b92cf7907"

# https://hyperevmscan.io/address/0x8ebA6fc4Ff6Ba4F12512DD56d0E4aaC6081f5274#readContract
# getReservesIncentivesData: a73ff12d177d8f1ec938c3ba0e87d33524dd5594
# abi: https://raw.githubusercontent.com/0xVanfer/abigen/main/aave/aaveUiIncentiveDataProviderV3/aaveUiIncentiveDataProviderV3.go
HL_EVM_HYUSDT = "0x1Ca7e21B2dAa5Ab2eB9de7cf8f34dCf9c8683007"

# https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/hypercore-less-than-greater-than-hyperevm-transfers
HL_SWAPS = {
    HL_DEX_HYPE: ("0x2222222222222222222222222222222222222222", None),
    HL_DEX_USDE: ("0x20000000000000000000000000000000000000eb", HL_EVM_USDE),
    HL_DEX_UETH: ("0x20000000000000000000000000000000000000dd", HL_EVM_UETH),
}

HL_FELIX_USDE = "0x835FEBF893c6DdDee5CF762B0f8e31C5B06938ab"
HL_SENTIMENT_USDE = "0xe45E7272DA7208C7a137505dFB9491e330BF1a4e"


def evm_transfer(w3: Web3, ac: LocalAccount, taddr: str, amount: int) -> str:
    return evm_call(w3, ac, {"to": to_addr(w3, taddr), "value": amount})


def _to_wei_evm(w3: Web3, ac: LocalAccount, amount: float) -> int:
    assert amount > 0 or amount == -1, "Amount must be positive or -1 for all balance"

    if amount == -1:
        precision = 10 ** (18 - 4)  # keep 4 decimal places
        bal = w3.eth.get_balance(ac.address)
        min_gas = w3.eth.estimate_gas({"to": ac.address, "from": ac.address, "value": 0})
        min_gas *= 2  # safety buffer
        new_bal = bal - int(min_gas * w3.eth.gas_price)
        new_bal = int(round(new_bal / precision)) * precision
        return new_bal

    return to_wei(Decimal(amount), "ether")


def _to_wei_erc(w3: Web3, ac: LocalAccount, caddr: str, amount: float) -> int:
    assert amount > 0 or amount == -1, "Amount must be positive or -1 for all balance"

    if amount == -1:
        return Erc20.balance(w3, caddr, ac.address)

    decimals = Erc20.decimals(w3, caddr)
    return int(amount * 10**decimals)


# MARK: Hyperliquid


def hl_deposit(w3: Web3, ac: LocalAccount, amount_dec: float) -> str:
    assert w3.eth.chain_id == 42161, "Not on Arbitrum One network"
    assert amount_dec >= 10.0, f"Deposit amount too low: {amount_dec} USDC"

    amount_wei = int(amount_dec * 1e6)
    amount_now = Erc20.balance(w3, ARB_USDC, ac.address)
    assert amount_now >= amount_wei, f"Not enough USDC balance: {amount_now / 1e6} USDC"

    return Erc20.transfer(w3, ac, ARB_USDC, HL_BRIDGE_ADDR, amount_wei)


def hl_perp_usdc(hl: Exchange) -> float:
    rs = hl.info.user_state(hl.wallet.address)
    # logger.debug(f"hl_perp_usdc: {json.dumps(rs)}")
    return float(rs["withdrawable"])


def hl_transfer(hl: Exchange, src: str, dst: str, token: str, amount: float):
    assert amount > 0 or amount == -1, "Amount must be positive or -1 for all balance"

    routes = {
        ("perp", "spot"): [HL_DEX_USDC],
        ("spot", "perp"): [HL_DEX_USDC],
        ("spot", "evm"): [token],  # any token
        ("evm", "spot"): [token],  # any token
    }

    route = routes.get((src, dst))
    assert route is not None, f"Transfer route not supported: {src} -> {dst}"
    assert token in route, f"Token {token} not supported for {src} -> {dst} transfer"

    dst_wal = str(hl.wallet.address)
    if dst == "evm":
        swap = HL_SWAPS.get(token)
        assert swap is not None, f"No EVM destination wallet for token {token}"
        dst_wal = swap[0]

    if src == "evm":
        w3 = Web3(Web3.HTTPProvider(HLE_RPC_URL))
        baddr, caddr = HL_SWAPS[token]
        logger.debug(f"hl_transfer evm -> {dst}: {token} {amount=}, {baddr=}, {caddr=}")

        if caddr is None:  # HYPE transfer from HL to EVM
            evm_amount = _to_wei_evm(w3, hl.wallet, amount)
            evm_transfer(w3, hl.wallet, baddr, evm_amount)
        else:  # USDE transfer from HL to EVM
            evm_amount = _to_wei_erc(w3, hl.wallet, caddr, amount)
            Erc20.transfer(w3, hl.wallet, caddr, baddr, evm_amount)
    else:
        assert amount is not None, "Amount must be specified for HL -> evm transfers"
        src_dex = "" if src == "perp" else "spot"
        dst_dex = "" if dst == "perp" else "spot"

        if src == "spot" and dst == "perp":  # only usdc supported
            amount = floor_to_precision(amount, 0.01)

        rs = hl.send_asset(
            destination=dst_wal,
            source_dex=src_dex,
            destination_dex=dst_dex,
            token=token,
            amount=amount,
        )

        logger.debug(f"hl_transfer {src} -> {dst} {token} {amount=}: {rs}")
        assert rs["status"] == "ok", "hl_transfer failed"

    return True


@lru_cache
def hl_spot_pair(hl: Exchange, pair: str):
    rs = hl.info.spot_meta()
    t1, t2 = pair.split("/")
    t1 = next(x for x in rs["tokens"] if x["name"] == t1)
    t2 = next(x for x in rs["tokens"] if x["name"] == t2)
    assert t1 and t2, f"Token not found: {t1} or {t2}"

    pairs = {tuple(x["tokens"]): x for x in rs["universe"]}
    pair_cfg = pairs.get((t1["index"], t2["index"])) or pairs.get((t2["index"], t1["index"]))
    assert pair_cfg, f"Pair not found: {pair}"

    t1, t2 = (t1, t2) if pair_cfg["tokens"][0] == t1["index"] else (t2, t1)
    pairid = pair_cfg["name"]
    return pairid, t1, t2


def hl_token_bal(hl: Exchange, idx_or_tkr: int | str) -> float:
    rs = hl.info.spot_user_state(hl.wallet.address)
    search_by = "token" if isinstance(idx_or_tkr, int) else "coin"
    rs = [x for x in rs["balances"] if x[search_by] == idx_or_tkr]
    rs = float(rs[0]["total"]) if rs else 0.0
    return rs


def hl_order(
    hl: Exchange,
    pair: str,
    is_buy: bool = True,
    asset_sz: float | None = None,
    quote_sz: float | None = None,
    slippage: float = 0.05,
):
    if (asset_sz is None and quote_sz is None) or (asset_sz is not None and quote_sz is not None):
        raise ValueError("Specify either asset_sz or quote_sz")

    pairid, t1, t2 = hl_spot_pair(hl, pair)
    mid_price = float(hl.info.all_mids()[pairid])

    fname = t2["name"] if is_buy else t1["name"]
    tname = t1["name"] if is_buy else t2["name"]
    opname = f"{pairid} {fname} -> {tname}"

    MIN_ORDER = 10.0  # in USDC
    sz, px = None, None

    if quote_sz is not None:
        quote_sz = hl_token_bal(hl, t2["index"]) if quote_sz == -1 else quote_sz
        assert quote_sz > 0, f"{quote_sz=} must be positive"

        sz_step = t1["szDecimals"]
        sz = max(quote_sz, MIN_ORDER) / mid_price
        sz = [sz, sz + 1 / 10**sz_step]
        sz = [round(x, sz_step) for x in sz]
        sz = min(x for x in sz if x * mid_price >= MIN_ORDER)

        px = 1 + slippage if is_buy else 1 - slippage
        px = round(mid_price * px, 3)

    if asset_sz is not None:
        asset_sz = hl_token_bal(hl, t1["index"]) if asset_sz == -1 else asset_sz
        assert asset_sz > 0, f"{asset_sz=} must be positive"

        sz = round(asset_sz, t1["szDecimals"])
        px = 1 + slippage if is_buy else 1 - slippage
        px = round(mid_price * px, 3)

    logger.debug(f"{opname}: {mid_price=} {sz=} {px=} ({asset_sz=}, {quote_sz=})")
    assert sz is not None and px is not None, "sz or px is None"
    # todo: neet to check against read balances
    # assert sz * mid_price >= MIN_ORDER, f"Order size too low: {sz * mid_price}, min {MIN_ORDER}"

    # rs = hl.market_open(pairid, is_buy, sz)
    rs = hl.order(pairid, is_buy, sz, px, {"limit": {"tif": "FrontendMarket"}})  # type: ignore
    # rs = hl.order(pairid, is_buy, sz, px, {"limit": {"tif": "Ioc"}})
    logger.debug(rs)
    return rs


# MARK: Main


def is_proxy_error(e: Exception) -> bool:
    return (
        isinstance(e, requests.exceptions.ProxyError)
        or isinstance(e, httpx.ProxyError)
        or isinstance(e, httpx.ReadTimeout)
    )


def floor_to_precision(value: float, precision: float) -> float:
    d_value = Decimal(str(value))
    d_precision = Decimal(str(precision))

    rounded = d_value.quantize(d_precision, rounding=ROUND_DOWN)
    return float(rounded)


def _is_finished_state(state: dict) -> bool:
    try:
        return state["act_name"] == "act_final" and state["act_done"]
    except KeyError:
        return False


class WorkerState:
    def __init__(self, state_file: str, addr: str):
        self._full_state = []  # list of all addr states
        self._addr_state = {}  # state for this addr
        self._state_file = state_file

        utctime = datetime.now(tz=UTC).isoformat(timespec="minutes").split("+")[0]
        default_state = {"_addr": addr, "act_name": None, "act_done": False, "_time": utctime}

        def get_addr_state(items: list) -> dict:
            items = [x for x in items if x.get("_addr") == addr]
            items = [x for x in items if not _is_finished_state(x)]
            assert len(items) <= 1, "Multiple active states for the same address"
            return items[0] if items else default_state

        try:
            with open(state_file, "r") as fp:
                items = json.load(fp)
                assert isinstance(items, list), "State file format invalid"

                addr_state = get_addr_state(items)

                # move addr_state to the front
                items = [x for x in items if x != addr_state]
                items.insert(0, addr_state)

                self._full_state = items
                self._addr_state = addr_state
        except FileNotFoundError:
            pass

    def dump(self):
        with open(self._state_file, "w") as fp:
            json.dump(self._full_state, fp, indent=2, default=str, sort_keys=True)

    def setitem(self, key: str, val):
        self._addr_state[key] = val
        self.dump()

    def getitem(self, key: str, default=None):
        return self._addr_state.get(key, default)

    def delitem(self, key: str):
        if key in self._addr_state:
            del self._addr_state[key]
            self.dump()

    def __contains__(self, key: str):
        return key in self._addr_state

    def getorfail(self, key: str):
        if key not in self._addr_state:
            raise KeyError(f"Key not found in state: {key}")
        return self._addr_state[key]


class Worker:
    def __init__(self, acc: LocalAccount, cex_addr: str | None = None):
        self.acc = acc
        self.rnd = random.Random(self.acc.address.lower())

        proxy_txt = CltManager.get_proxy_txt(acc.address)
        proxy = CltManager.get_proxy(acc.address)

        w3_kw = {"proxies": {"http": proxy, "https": proxy}} if proxy else None
        logger.debug(f"Acc: {self.acc.address} | CEX: {cex_addr} | Proxy: {proxy_txt}")

        self.w3_arb = Web3(Web3.HTTPProvider(ARB_RPC_URL, request_kwargs=w3_kw))
        self.w3_hle = Web3(Web3.HTTPProvider(HLE_RPC_URL, request_kwargs=w3_kw))
        self.w3_eth = Web3(Web3.HTTPProvider(ETH_RPC_URL, request_kwargs=w3_kw))
        self.hl = Exchange(wallet=self.acc, base_url=HL_API_URL)  # todo: proxy
        self.hl.session.proxies = w3_kw["proxies"] if w3_kw else None

        self.state = WorkerState(".hl-workers.json", self.acc.address)
        self.cex_addr = cex_addr

    def act_check(self):
        legals = [
            (Hyperliquid.sign_terms, "legal_hyperliquid"),
            (HyperUnit.sign_terms, "legal_hyperunit"),
        ]

        for func, state_key in legals:
            status = self.state.getitem(state_key, False)
            if not status:
                func(self.acc)
                self.state.setitem(state_key, True)

        # raise NotImplementedError()

    def act_cex_withdraw_usdc(self):
        # todo: unfinished action
        if WrkCfg.cex_withdraw is False:
            logger.info("CEX withdraw disabled in config")
            return

        prices = Valantis.prices()
        ueth_price = prices.get(HL_EVM_UETH.lower())
        assert ueth_price is not None, "UETH price not found"

        lend_part = 0.7
        lend_safe_leverage = 0.6
        min_unit_dep = 0.05
        safety_buf = 1.1
        min_dep = 1 / lend_part / lend_safe_leverage * min_unit_dep * safety_buf * ueth_price
        logger.debug(f"Min CEX withdraw amount calculated: {min_dep:.4f} USDC")

        amount = WrkCfg.cex_withdraw_amount
        if amount < min_dep:
            logger.error(f"CEX withdraw amount too low: {amount} < {min_dep}")
            exit(1)

        was_usdc = Erc20.balance_dec(self.w3_arb, ARB_USDC, self.acc.address)
        self.state.setitem("_usdc_before_cex_withdraw", was_usdc)

        bybit_withdraw(chain="ARBI", coin="USDC", addr=self.acc.address, amount=amount)
        logger.info(f"CEX withdraw requested: {amount} USDC to {self.acc.address}")

    def act_cex_withdraw_usdc_wait(self):
        if WrkCfg.cex_withdraw is False:
            return

        was_usdc = self.state.getitem("_usdc_before_cex_withdraw")
        assert was_usdc is not None, "CEX withdraw state not found"
        while True:
            time.sleep(15)
            now_usdc = Erc20.balance_dec(self.w3_arb, ARB_USDC, self.acc.address)
            if now_usdc > was_usdc:
                logger.info(f"CEX withdraw completed: new USDC balance {now_usdc:.2f}")
                self.state.delitem("_usdc_before_cex_withdraw")
                break

            logger.info(f"Waiting for CEX withdraw... current USDC balance: {now_usdc:.2f}")

    def act_hl_deposit(self):
        arb_eth = self.w3_arb.eth.get_balance(self.acc.address) / 1e18
        assert arb_eth > 0.0001, f"Not enough ARB balance to transfer: {arb_eth} ETH"

        min_dep = 100.0  # minimum USDC balance to proceed
        arb_bal = Erc20.balance_dec(self.w3_arb, ARB_USDC, self.acc.address)
        assert arb_bal >= min_dep, f"Min USDC balance not met: {arb_bal} < {min_dep}"

        arb_bal = floor_to_precision(arb_bal, 1.0)

        # keep for history
        self.state.setitem("_usdc_before", arb_bal)

        arb_bal = min(arb_bal, WrkCfg.hl_max_dep) if WrkCfg.hl_max_dep is not None else arb_bal

        hl_was = hl_perp_usdc(self.hl)
        logger.info(f"HL deposit {arb_bal:.2f} USDC, HL balance: {hl_was:.2f} USDC")

        self.state.setitem("hl_perp_usdc", hl_was)
        hl_deposit(self.w3_arb, self.acc, arb_bal)

    def act_hl_deposit_wait(self):
        hl_was = self.state.getitem("hl_perp_usdc")
        assert hl_was is not None, "HL deposit state not found"

        while True:
            hl_now = hl_perp_usdc(self.hl)
            if hl_now > hl_was:
                logger.info(f"HL deposit completed, new HL balance: {hl_now:.2f} USDC")
                self.state.delitem("hl_perp_usdc")
                break

            logger.info(f"Waiting for HL deposit... current HL balance: {hl_now:.2f} USDC")
            time.sleep(5)

    def act_hl_usdc2spot(self):
        perp_usdc_dec = hl_perp_usdc(self.hl)
        assert perp_usdc_dec > 0, f"No USDC balance in HL perp account: {perp_usdc_dec}"
        hl_transfer(self.hl, "perp", "spot", HL_DEX_USDC, perp_usdc_dec)

    def act_hl_spot_buy_hype(self):
        # check how many HYPE we already have (in case of second run)
        hype_bal1 = hl_token_bal(self.hl, "HYPE")
        hype_bal2 = self.w3_hle.eth.get_balance(self.acc.address)
        logger.debug(f"Current HYPE balance: HL={hype_bal1:.2f}, EVM={hype_bal2 / 1e18:.4f}")

        total_hype = hype_bal1 + hype_bal2 / 1e18
        if total_hype >= 0.1:
            logger.info(f"Enough HYPE balance ({total_hype:.4f}), skipping buy")
            return

        hl_order(self.hl, "HYPE/USDC", is_buy=True, quote_sz=10)  # buy for 10 USDC

    def act_hl_spot_buy_usde(self):
        usdc_now = hl_token_bal(self.hl, "USDC")  # keep 10 USDC for future use
        usdc_dep = usdc_now - 10.0
        assert usdc_dep >= 10.0, f"Not enough USDC to buy USDE: {usdc_now}"
        hl_order(self.hl, "USDE/USDC", is_buy=True, quote_sz=usdc_dep)

    def act_hl_move_hype_to_evm(self):
        bal1 = hl_token_bal(self.hl, "HYPE")
        bal2 = floor_to_precision(bal1 * 0.9, 0.01)
        if bal2 < 0.01:
            logger.warning(f"Low HYPE balance to move: {bal1} -> {bal2}. Second run?")
            return

        logger.debug(f"HL HYPE balance: {bal1=}, moving {bal2=}")
        hl_transfer(self.hl, "spot", "evm", HL_DEX_HYPE, bal2)

    def act_hl_move_ueth_to_evm(self):
        bal = hl_token_bal(self.hl, "UETH")
        logger.debug(f"HL UETH balance: {bal=}, moving all")
        hl_transfer(self.hl, "spot", "evm", HL_DEX_UETH, bal)

    def act_hl_move_usde_to_evm(self):
        bal = hl_token_bal(self.hl, "USDE")
        hl_transfer(self.hl, "spot", "evm", HL_DEX_USDE, bal)

    def act_unit_dep_eth(self):
        eth_bal = self.w3_eth.eth.get_balance(self.acc.address)
        eth_dep = eth_bal - int(0.003 * 1e18)  # keep some founds on wallet ~ 6-8 USD
        eth_dep = int(eth_dep / 1e14 * 1e14)  # floor to 0.0001 ETH precision

        bal_dec = eth_bal / 1e18
        dep_dec = eth_dep / 1e18
        left_dec = (eth_bal - eth_dep) / 1e18
        logger.debug(f"ETH now: {bal_dec:.6f}, dep: {dep_dec:.6f}, left: {left_dec:.6f}")
        if dep_dec < 0.05:
            logger.error(f"Not enough balance for Unit deposit: {dep_dec} ETH. Skipping.")
            exit(1)

        dep_addr = HyperUnit.get_dep_addr(self.acc, "ethereum", "hyperliquid", "eth")
        logger.debug(f"Unit ETH deposit address: {dep_addr}")

        expect_ops = len(HyperUnit.get_ops(self.acc)) + 1
        evm_transfer(self.w3_eth, self.acc, dep_addr, eth_dep)
        self.state.setitem("unit_expect_ops", expect_ops)

    def act_unit_dep_eth_wait(self):
        expect_ops = self.state.getorfail("unit_expect_ops")
        HyperUnit.wait_ongoing_ops(self.acc, expect_ops)
        self.state.delitem("unit_expect_ops")

    def act_swap_prepare_plan(self):
        vs_share = self.rnd.randint(200, 300) / 1000.0  # 20% - 30% of total USDE balance
        v1_share = self.rnd.randint(400, 600) / 1000.0  # 40% - 60% to vault1
        v2_share = 1.0 - v1_share

        bal = Erc20.balance_dec(self.w3_hle, HL_EVM_USDE, self.acc.address)
        v1_bal = floor_to_precision(bal * vs_share * v1_share, 0.1)
        v2_bal = floor_to_precision(bal * vs_share * v2_share, 0.1)
        logger.debug(f"Vaults: {vs_share:.1%} of {bal:.2f} – {v1_bal} / {v2_bal}")

        left_bal = bal - v1_bal - v2_bal
        swap1_bal = floor_to_precision(left_bal * 0.5, 0.1)
        swap2_bal = floor_to_precision(left_bal - swap1_bal, 0.1)
        logger.debug(f"Swaps: {left_bal:.2f} – {swap1_bal} / {swap2_bal}")

        self.state.setitem("vault_felix", v1_bal)
        self.state.setitem("vault_sentiment", v2_bal)
        self.state.setitem("swap_hypurr", swap1_bal)
        self.state.setitem("swap_valantis", swap2_bal)

    def act_supply_felix(self):
        dep = self.state.getorfail("vault_felix")
        dep = _to_wei_erc(self.w3_hle, self.acc, HL_EVM_USDE, dep)
        Erc20.check_approve(self.w3_hle, self.acc, HL_EVM_USDE, HL_FELIX_USDE, dep)
        Erc4626.deposit(self.w3_hle, self.acc, HL_FELIX_USDE, dep)

    def act_supply_sentiment(self):
        dep = self.state.getorfail("vault_sentiment")
        dep = _to_wei_erc(self.w3_hle, self.acc, HL_EVM_USDE, dep)
        Erc20.check_approve(self.w3_hle, self.acc, HL_EVM_USDE, HL_SENTIMENT_USDE, dep)
        Erc4626.deposit(self.w3_hle, self.acc, HL_SENTIMENT_USDE, dep)

    def act_swap_usde2usdt_hypurr(self):
        dep = self.state.getorfail("swap_hypurr")
        dep = _to_wei_erc(self.w3_hle, self.acc, HL_EVM_USDE, dep)
        Hypurr.swap(self.w3_hle, self.acc, HL_EVM_USDE, HL_EVM_USDT, dep)

    def act_swap_usde2usdt_valantis(self):
        dep = self.state.getorfail("swap_valantis")
        dep = _to_wei_erc(self.w3_hle, self.acc, HL_EVM_USDE, dep)
        Valantis.swap(self.w3_hle, self.acc, HL_EVM_USDE, HL_EVM_USDT, dep)

    def act_hypurr_supply_usdt(self):
        bal = Erc20.balance(self.w3_hle, HL_EVM_USDT, self.acc.address)
        bal = int(bal * 0.985)  # supply 98.5% of balance
        Hypurr.supply(self.w3_hle, self.acc, HL_EVM_USDT, bal)

    def act_hypurr_borrow_ueth(self):
        dat = Hypurr.get_account_data(self.w3_hle, self.acc.address)
        decimals = 10**8  # USD-like token

        all_bal = dat["totalCollateral"] / decimals
        can_bal = dat["availableBorrows"] / decimals
        max_rate = dat["availableBorrows"] / dat["totalCollateral"]
        safe_rate = self.rnd.uniform(0.5, max_rate * 0.85)
        safe_bal = all_bal * safe_rate
        logger.info(f"Borrow rates {max_rate=:.2%}% {safe_rate=:.2%}%")
        logger.info(f"Borrow collateral {all_bal=:.2f} {can_bal=:.2f} {safe_bal=:.2f}")

        prices = Valantis.prices()
        ueth_price = prices.get(HL_EVM_UETH.lower())
        assert ueth_price is not None, "UETH price not found"
        safe_ueth = floor_to_precision(safe_bal / ueth_price, 0.0001)
        safe_ueth_wei = _to_wei_erc(self.w3_hle, self.acc, HL_EVM_UETH, safe_ueth)
        logger.info(f"Borrowing UETH {safe_ueth:.4f} ({safe_ueth_wei} wei) ~ {ueth_price:=.4f}")

        Hypurr.borrow(self.w3_hle, self.acc, HL_EVM_UETH, safe_ueth_wei)

    def act_swap_usdt2ueth_hypurr(self):
        # to repay borrowed percentage of UETH, we need to get some extra UETH
        bal = Erc20.balance(self.w3_hle, HL_EVM_USDT, self.acc.address)
        Hypurr.swap(self.w3_hle, self.acc, HL_EVM_USDT, HL_EVM_UETH, bal)

    def act_hypurr_repay_ueth(self):
        decimals = Erc20.decimals(self.w3_hle, HL_EVM_UETH)

        # just repay all balance, hyppurr will handle max repayable amount
        bal1 = Erc20.balance(self.w3_hle, HL_EVM_UETH, self.acc.address)
        Hypurr.repay(self.w3_hle, self.acc, HL_EVM_UETH, bal1)
        bal2 = Erc20.balance(self.w3_hle, HL_EVM_UETH, self.acc.address)

        bal1, bal2 = bal1 / (10**decimals), bal2 / (10**decimals)
        logger.info(f"UETH balance after repay: {bal2} (was {bal1})")

    def act_hypurr_redeem_usdt(self):
        # keep small amount for percentage fees
        bal = max(Erc20.balance(self.w3_hle, HL_EVM_HYUSDT, self.acc.address) - 5, 0)
        Hypurr.withdraw(self.w3_hle, self.acc, HL_EVM_USDT, bal)

    def act_swap_ueth2usdt_hypurr(self):
        bal = Erc20.balance(self.w3_hle, HL_EVM_UETH, self.acc.address)
        Hypurr.swap(self.w3_hle, self.acc, HL_EVM_UETH, HL_EVM_USDT, bal)

    def act_swap_usdt2usde_hypurr(self):
        bal = Erc20.balance(self.w3_hle, HL_EVM_USDT, self.acc.address)
        dep = int(bal * self.rnd.uniform(0.45, 0.55))  # swap 45% - 55% of USDT balance
        logger.debug(f"Swapping USDT to USDE via Hypurr: {dep} (all {bal})")
        Hypurr.swap(self.w3_hle, self.acc, HL_EVM_USDT, HL_EVM_USDE, dep)

    def act_swap_usdt2usde_valantis(self):
        bal = Erc20.balance(self.w3_hle, HL_EVM_USDT, self.acc.address)
        logger.debug(f"Swapping USDT to USDE via Valantis: {bal}")
        Valantis.swap(self.w3_hle, self.acc, HL_EVM_USDT, HL_EVM_USDE, bal)

    def act_redeem_felix(self):
        bal = Erc20.balance(self.w3_hle, HL_FELIX_USDE, self.acc.address)
        # Erc20.check_approve(self.w3_hlc, self.acc, HL_FELIX_USDE, HL_FELIX_USDE, bal)
        logger.info(f"Felix USDE redeem: {bal} shares")
        Erc4626.redeem(self.w3_hle, self.acc, HL_FELIX_USDE, bal)

    def act_redeem_sentiment(self):
        bal = Erc4626.max_withdraw(self.w3_hle, HL_SENTIMENT_USDE, self.acc.address)
        # bal = Erc20.balance(self.w3_hlc, HL_SENTIMENT_USDE, self.acc.address)
        # Erc20.check_approve(self.w3_hlc, self.acc, HL_SENTIMENT_USDE, HL_SENTIMENT_USDE, bal)
        logger.info(f"Sentiment USDE redeem: {bal} shares")
        Erc4626.withdraw(self.w3_hle, self.acc, HL_SENTIMENT_USDE, bal)

    def act_hl_usde_from_evm(self):
        hl_transfer(self.hl, "evm", "spot", HL_DEX_USDE, -1)  # transfer all USDE

    def act_hl_sell_usde(self):
        hl_order(self.hl, "USDE/USDC", is_buy=False, asset_sz=-1)  # sell all USDE

    def act_hl_spot2perp_usdc(self):
        bal = hl_token_bal(self.hl, "USDC")
        hl_transfer(self.hl, "spot", "perp", HL_DEX_USDC, bal)

    def act_hl_withdraw(self):
        usdc_was = Erc20.balance_dec(self.w3_arb, ARB_USDC, self.acc.address)
        self.state.setitem("arb_usdc_before", usdc_was)

        hl_bal = hl_perp_usdc(self.hl)
        assert hl_bal > 0, f"No USDC balance in HL perp account: {hl_bal}"
        logger.info(f"Withdrawing {hl_bal:.2f} USDC from HL perp account")

        self.hl.withdraw_from_bridge(hl_bal, self.acc.address)

    def act_hl_withdraw_wait(self):
        usdc_was = self.state.getorfail("arb_usdc_before")

        while True:
            usdc_now = Erc20.balance_dec(self.w3_arb, ARB_USDC, self.acc.address)
            if usdc_now > usdc_was:
                logger.info(f"HL withdraw completed, new USDC balance: {usdc_now:.2f}")
                self.state.delitem("arb_usdc_before")
                break

            logger.info(f"Waiting for HL withdraw... current USDC balance: {usdc_now:.2f}")
            time.sleep(15)

    def act_unit_withdraw_ueth(self):
        # move UETH from EVM to Core
        evm_bal = Erc20.balance(self.w3_hle, HL_EVM_UETH, self.acc.address)
        logger.debug(f"HL UETH balance on EVM: {evm_bal}, withdrawing to Core")
        if evm_bal > int(0.0001 * 1e18):
            hl_transfer(self.hl, "evm", "spot", HL_DEX_UETH, -1)

        hl_bal = hl_token_bal(self.hl, "UETH")
        logger.debug(f"HL UETH balance on Core: {hl_bal}, withdrawing to Unit")
        if hl_bal < 0.05:
            logger.error(f"Not enough HL UETH balance to withdraw: {hl_bal}")
            exit(1)

        expect_ops = len(HyperUnit.get_ops(self.acc)) + 1
        HyperUnit.widthdraw(self.acc, HL_DEX_UETH, hl_bal)
        self.state.setitem("unit_expect_ops", expect_ops)

    def act_unit_withdraw_ueth_wait(self):
        expect_ops = self.state.getorfail("unit_expect_ops")
        HyperUnit.wait_ongoing_ops(self.acc, expect_ops)
        self.state.delitem("unit_expect_ops")

    def act_final(self):
        if "_usdc_before" in self.state:
            was_bal = self.state.getorfail("_usdc_before")
            now_bal = Erc20.balance_dec(self.w3_arb, ARB_USDC, self.acc.address)
            now_bal = floor_to_precision(now_bal, 0.01)

            cost = floor_to_precision(was_bal - now_bal, 0.01)
            self.state.setitem("_cost", cost)
            self.state.delitem("_usdc_before")
        else:
            cost = self.state.getorfail("_cost")

        if self.cex_addr is not None:
            now_bal_wei = Erc20.balance(self.w3_arb, ARB_USDC, self.acc.address)
            Erc20.transfer(
                self.w3_arb,
                self.acc,
                ARB_USDC,
                to_addr(self.w3_arb, self.cex_addr),
                now_bal_wei,
            )

        logger.info(f"Worker: done, cost = {cost:.2f} USDC")
        cmd_say("Hyperliquid worker done!", repeat=1)

    def act_pause_flow(self):
        raise NotImplementedError()

    def _exec_fn(self, fn):
        act_name = fn.__name__
        now_retries, max_retries = 0, WrkCfg.max_retries

        known_patterns = [
            (RuntimeError, "tx failed:"),
            (web3.exceptions.Web3RPCError, "invalid block height:"),
            (web3.exceptions.Web3RPCError, "out of gas: gas required exceeds:"),
            (httpx.HTTPStatusError, "500 internal server error"),
        ]

        while True:
            now_retries += 1
            try:
                logger.info(f"Worker: executing action '{act_name}'")
                return fn()
            except Exception as e:
                logger.error(f"Worker: failed '{act_name}' {type(e)}: {e}")

                # always retry on proxy errors
                if is_proxy_error(e):
                    time.sleep(2.0)
                    continue

                err_txt = str(e).lower()
                known_err = any(isinstance(e, x[0]) and x[1] in err_txt for x in known_patterns)
                fast_exit = WrkCfg.fail_fast_on_unknown_err and not known_err

                # fail fast on unknown errors
                max_retries = max_retries if not fast_exit else 0
                rnd_sec = random.uniform(10, 30)
                rmsg = f"retry {now_retries}/{max_retries}, {known_err=}"
                logger.info(f"Worker: retrying '{act_name}' in {rnd_sec:.2f} sec ({rmsg})")

                if now_retries >= max_retries:
                    break

                time.sleep(rnd_sec)
                continue

        logger.error(f"Worker: failed '{act_name}' after {now_retries} retries, exiting")
        exit(1)

    def run(self):
        routes, mapping = self.route1(), {}
        for i in range(len(routes)):
            fn = routes[i]
            next_fn = routes[i + 1] if i + 1 < len(routes) else None
            mapping[fn.__name__] = {"func": fn, "next": next_fn.__name__ if next_fn else None}

        while True:
            act_name = self.state.getitem("act_name") or routes[0].__name__
            act_done = self.state.getitem("act_done") or False

            act = mapping.get(act_name)
            if act is None:
                logger.error(f"Worker: unknown {act_name=}")
                exit(1)

            if act_done:
                if act["next"] is None:
                    logger.info("Worker: all actions completed")
                    break

                # logger.info(f"Worker run: moving to next action {act['next']}")
                self.state.setitem("act_name", act["next"])
                self.state.setitem("act_done", False)
                continue

            print("-" * 60)
            self._exec_fn(act["func"])
            self.state.setitem("act_done", True)

            rnd_sleep = self.rnd.uniform(5.0, 10.0)
            logger.info(f"Worker: sleeping for {rnd_sleep:.2f} sec before next action")
            time.sleep(rnd_sleep)

    def route1(self):
        return [
            self.act_check,
            self.act_cex_withdraw_usdc,
            self.act_cex_withdraw_usdc_wait,
            self.act_hl_deposit,
            self.act_hl_deposit_wait,
            self.act_hl_usdc2spot,
            self.act_hl_spot_buy_hype,
            self.act_hl_spot_buy_usde,
            self.act_hl_move_hype_to_evm,
            self.act_hl_move_usde_to_evm,
            self.act_swap_prepare_plan,
            self.act_supply_felix,
            self.act_supply_sentiment,
            self.act_swap_usde2usdt_hypurr,
            self.act_swap_usde2usdt_valantis,
            self.act_hypurr_supply_usdt,
            self.act_hypurr_borrow_ueth,
            # self.act_pause_flow, # todo: something better then out / in
            self.act_unit_withdraw_ueth,
            self.act_unit_withdraw_ueth_wait,
            self.act_unit_dep_eth,
            self.act_unit_dep_eth_wait,
            self.act_hl_move_ueth_to_evm,
            self.act_swap_usdt2ueth_hypurr,
            self.act_hypurr_repay_ueth,
            self.act_hypurr_redeem_usdt,
            self.act_swap_ueth2usdt_hypurr,
            self.act_swap_usdt2usde_hypurr,
            self.act_swap_usdt2usde_valantis,
            self.act_redeem_felix,
            self.act_redeem_sentiment,
            self.act_hl_usde_from_evm,
            self.act_hl_sell_usde,
            self.act_hl_spot2perp_usdc,
            self.act_hl_withdraw,
            self.act_hl_withdraw_wait,
            self.act_final,
        ]


def main():
    CltManager.load_proxies("_proxies.txt")
    cex_mapping = load_cex_mapping("_cex_map.txt")

    privkey = os.getenv("EVM_PRIV_KEY")
    assert privkey is not None, "EVM_PRIV_KEY not set"

    acc = Web3().eth.account.from_key(privkey)
    cex_addr = cex_mapping.get(str(acc.address).lower())
    assert cex_addr, f"CEX address not found for {acc.address}"

    wrk = Worker(acc, cex_addr)
    wrk.run()


if __name__ == "__main__":
    main()
