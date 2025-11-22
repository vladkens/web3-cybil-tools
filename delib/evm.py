import json
import random
import time
from typing import cast

import web3.exceptions
from eth_account.signers.local import LocalAccount
from eth_utils.currency import to_wei
from loguru import logger
from web3 import Web3
from web3.contract.contract import ContractFunction
from web3.types import TxParams


def to_addr(w3: Web3, addr: str | int):
    addr = hex(addr) if isinstance(addr, int) else addr
    return w3.to_checksum_address(addr)


def _dynamic_fee_params(w3: Web3) -> dict:
    latest = w3.eth.get_block("latest")
    base_fee = latest.get("baseFeePerGas")

    if base_fee is None:
        return {"gasPrice": w3.eth.gas_price}

    default_priority = to_wei("0.1", "gwei")

    try:
        priority = w3.eth.max_priority_fee
        priority = max(priority, default_priority)
    except Exception:
        priority = default_priority

    max_fee = int(base_fee + priority * 1.3)
    return {"type": 2, "maxPriorityFeePerGas": max_fee, "maxFeePerGas": max_fee}


def _evm_dump_params(params: TxParams):
    kv = params.copy()
    if "data" in kv:
        # truncate long data
        kv["data"] = f"{kv['data'][:16]}..."  # type: ignore

    return json.dumps(kv)


def _evm_log_tx(w3: Web3, txid: str, params: TxParams):
    explorers = {
        1: "https://etherscan.io/tx",
        56: "https://bscscan.com/tx",
        999: "https://hyperevmscan.io/tx",
        42161: "https://arbiscan.io/tx",
    }

    txurl = explorers.get(w3.eth.chain_id)
    txurl = f"{txurl}/0x{txid}" if txurl else f"0x{txid}"
    logger.debug(f"Sent tx {txurl} {_evm_dump_params(params)}")


def _evm_call_internal(w3: Web3, ac: LocalAccount, params: TxParams, wait_timeout: int) -> str:
    params["chainId"] = w3.eth.chain_id
    params["nonce"] = w3.eth.get_transaction_count(ac.address)
    params["from"] = ac.address
    params.update(_dynamic_fee_params(w3))

    try:
        # gas can be passed in params directly or try to estimate it
        params["gas"] = w3.eth.estimate_gas(params)
    except web3.exceptions.ContractCustomError as e:
        logger.warning(f"Failed to estimate tx gas {type(e)}")

    assert "gas" in params, "Gas not set in tx params"
    assert params["gas"] >= 21000, f"Gas too low in tx params: {params['gas']}"
    params["gas"] = int(params["gas"] * 1.2)  # safety buffer

    logger.debug(f"_evm_send: {_evm_dump_params(params)}")
    # exit(1)

    signed = ac.sign_transaction(params)
    txid = w3.eth.send_raw_transaction(signed.raw_transaction)
    _evm_log_tx(w3, txid.hex(), params)

    rc = w3.eth.wait_for_transaction_receipt(txid, timeout=wait_timeout)
    if rc.status != 1:
        raise RuntimeError(f"Tx failed: {txid}")

    return txid.hex()


def _prepare_params(acc: LocalAccount, pld: ContractFunction | TxParams | dict[str, str | int]):
    try:
        return cast(
            TxParams,
            pld.build_transaction({"from": acc.address})
            if isinstance(pld, ContractFunction)
            else pld,
        )
    except web3.exceptions.ContractLogicError as e:
        logger.error(f"Contract logic error: {e}")
        exit(1)


def evm_call(
    w3: Web3,
    ac: LocalAccount,
    pld: ContractFunction | TxParams | dict[str, str | int],
    wait_timeout=360,
) -> str:
    pld = _prepare_params(ac, pld)

    now_retries, max_retries = 0, 3
    while True:
        now_retries += 1
        try:
            return _evm_call_internal(w3, ac, pld, wait_timeout=wait_timeout)
        except web3.exceptions.Web3RPCError as e:
            can_retry = now_retries < max_retries
            rnd_sec = random.uniform(3.0, 6.0)

            rmsg = (
                f"retry in {rnd_sec:.1f}s... ({now_retries}/{max_retries})"
                if can_retry
                else "no more retries left."
            )

            logger.warning(f"RPC err {type(e)} – {rmsg}; {e}")
            if not can_retry:
                raise e

            time.sleep(rnd_sec)


class Erc20:
    @classmethod
    def balance(cls, w3: Web3, caddr: str, oaddr: str) -> int:
        caddr = to_addr(w3, caddr)
        oaddr = to_addr(w3, oaddr)

        fn = {
            "name": "balanceOf",
            "type": "function",
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "outputs": [{"name": "balance", "type": "uint256"}],
        }

        erc20 = w3.eth.contract(address=caddr, abi=[fn])
        balance = erc20.functions.balanceOf(oaddr).call()
        return balance

    @classmethod
    def decimals(cls, w3: Web3, caddr: str) -> int:
        caddr = to_addr(w3, caddr)

        fn = {
            "name": "decimals",
            "type": "function",
            "constant": True,
            "inputs": [],
            "outputs": [{"name": "", "type": "uint8"}],
        }

        erc20 = w3.eth.contract(address=caddr, abi=[fn])
        precision = erc20.functions.decimals().call()
        return int(precision)

    @classmethod
    def allowance(cls, w3: Web3, caddr: str, owner: str, spender: str) -> int:
        caddr = to_addr(w3, caddr)
        owner = to_addr(w3, owner)
        spender = to_addr(w3, spender)

        fn = {
            "name": "allowance",
            "type": "function",
            "constant": True,
            "inputs": [
                {"name": "_owner", "type": "address"},
                {"name": "_spender", "type": "address"},
            ],
            "outputs": [{"name": "remaining", "type": "uint256"}],
        }

        erc20 = w3.eth.contract(address=caddr, abi=[fn])
        allowance = erc20.functions.allowance(owner, spender).call()
        return allowance

    @classmethod
    def approve(cls, w3: Web3, ac, caddr: str, spender: str, amount: int) -> str:
        caddr = to_addr(w3, caddr)
        spender = to_addr(w3, spender)

        fn = {
            "name": "approve",
            "type": "function",
            "constant": False,
            "inputs": [
                {"name": "_spender", "type": "address"},
                {"name": "_value", "type": "uint256"},
            ],
            "outputs": [{"name": "", "type": "bool"}],
        }

        erc20 = w3.eth.contract(address=caddr, abi=[fn])
        return evm_call(w3, ac, erc20.functions.approve(spender, amount))

    @classmethod
    def transfer(cls, w3: Web3, ac, caddr: str, taddr: str, amount: int) -> str:
        caddr = to_addr(w3, caddr)
        taddr = to_addr(w3, taddr)

        bal = cls.balance(w3, caddr, ac.address)
        amount = bal if amount is None else amount
        assert bal >= amount, f"Not enough ERC20-token balance: {bal}, need {amount}"

        fn = {
            "name": "transfer",
            "type": "function",
            "constant": False,
            "inputs": [{"name": "_to", "type": "address"}, {"name": "_value", "type": "uint256"}],
            "outputs": [{"name": "", "type": "bool"}],
        }

        erc20 = w3.eth.contract(address=caddr, abi=[fn])
        return evm_call(w3, ac, erc20.functions.transfer(taddr, amount))

    # extra commands

    @classmethod
    def balance_dec(cls, w3: Web3, caddr: str, oaddr: str) -> int:
        decimals = cls.decimals(w3, caddr)
        balance = cls.balance(w3, caddr, oaddr)
        return balance / (10**decimals)

    @classmethod
    def check_approve(cls, w3: Web3, ac: LocalAccount, caddr: str, spender: str, amount: int):
        caddr = to_addr(w3, caddr)

        allowance = cls.allowance(w3, caddr, ac.address, spender)
        if allowance < amount:
            logger.debug(f"erc20 approve {caddr} for {spender} – {amount} (was: {allowance})")
            cls.approve(w3, ac, caddr, spender, amount)


class Erc4626:
    @classmethod
    def deposit(cls, w3: Web3, ac: LocalAccount, caddr: str, amount: int) -> str:
        caddr = to_addr(w3, caddr)

        fn = {
            "name": "deposit",
            "type": "function",
            "constant": False,
            "inputs": [
                {"name": "assets", "type": "uint256"},
                {"name": "receiver", "type": "address"},
            ],
            "outputs": [{"name": "shares", "type": "uint256"}],
        }

        erc4626 = w3.eth.contract(address=caddr, abi=[fn])
        return evm_call(w3, ac, erc4626.functions.deposit(amount, ac.address))

    @classmethod
    def redeem(cls, w3: Web3, ac: LocalAccount, caddr: str, shares: int) -> str:
        caddr = to_addr(w3, caddr)
        logger.debug(f"erc4626_redeem from {caddr} shares {shares} to {ac.address}")

        fn = {
            "name": "redeem",
            "type": "function",
            "constant": False,
            "inputs": [
                {"name": "shares", "type": "uint256"},
                {"name": "receiver", "type": "address"},
                {"name": "owner", "type": "address"},
            ],
            "outputs": [{"name": "assets", "type": "uint256"}],
        }

        erc4626 = w3.eth.contract(address=caddr, abi=[fn])
        rs = evm_call(w3, ac, erc4626.functions.redeem(shares, ac.address, ac.address))
        logger.debug(f"erc4626_redeem: {rs=}")
        return rs

    @classmethod
    def max_withdraw(cls, w3: Web3, caddr: str, oaddr: str) -> int:
        caddr = to_addr(w3, caddr)
        oaddr = to_addr(w3, oaddr)

        fn = {
            "name": "maxWithdraw",
            "type": "function",
            "constant": True,
            "inputs": [{"name": "owner", "type": "address"}],
            "outputs": [{"name": "maxAssets", "type": "uint256"}],
        }

        erc4626 = w3.eth.contract(address=caddr, abi=[fn])
        max_withdraw = erc4626.functions.maxWithdraw(oaddr).call()
        return max_withdraw

    @classmethod
    def withdraw(cls, w3: Web3, ac: LocalAccount, caddr: str, assets: int) -> str:
        caddr = to_addr(w3, caddr)
        logger.debug(f"erc4626_withdraw from {caddr} assets {assets} to {ac.address}")

        fn = {
            "name": "withdraw",
            "type": "function",
            "constant": False,
            "inputs": [
                {"name": "assets", "type": "uint256"},
                {"name": "receiver", "type": "address"},
                {"name": "owner", "type": "address"},
            ],
            "outputs": [{"name": "assets", "type": "uint256"}],
        }

        erc4626 = w3.eth.contract(address=caddr, abi=[fn])
        rs = evm_call(w3, ac, erc4626.functions.withdraw(assets, ac.address, ac.address))
        logger.debug(f"erc4626_withdraw: {rs=}")
        return rs
