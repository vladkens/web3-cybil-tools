import json
import textwrap
import time
from datetime import UTC, datetime

from eth_account.messages import encode_defunct, encode_typed_data
from hyperliquid.utils.signing import user_signed_payload
from loguru import logger

from .evm import Erc20, LocalAccount, Web3, _evm_dump_params, evm_call, to_addr
from .utils import CltManager

# DEFAULT_SLIPPAGE = 0.0075  # 0.75%
DEFAULT_SLIPPAGE = 0.01  # 1%
HYPURR_FI = "0xceCcE0EB9DD2Ef7996e01e25DD70e461F918A14b"


class SlippageError(Exception):
    pass


# https://app.hyperunit.xyz/
class HyperUnit:
    @classmethod
    def mk_clt(cls, addr: str):
        hdr = {"referer": "https://app.hyperunit.xyz/", "origin": "https://app.hyperunit.xyz"}
        return CltManager.create(addr, hdr)

    @classmethod
    def sign_terms(cls, acc: LocalAccount):
        clt = cls.mk_clt(acc.address)
        hdr = {
            "privy-app-id": "cm57ezkm403tzgjwk6oa5xyis",
            "privy-ca-id": "ecf696c2-6765-426d-9f3e-f79a790ff0dc",
            "privy-client": "react-auth:2.6.2",
        }

        rep = clt.post(
            "https://auth.privy.io/api/v1/siwe/init",
            headers=hdr,
            json={"address": str(acc.address)},
        )

        logger.debug(f"sign_hyperunit: {rep.status_code} {rep.text}")
        rep.raise_for_status()
        res = rep.json()

        cat = datetime.now(tz=UTC).isoformat(timespec="milliseconds")
        cat = cat.replace("+00:00", "Z")

        txt = f"""
        app.hyperunit.xyz wants you to sign in with your Ethereum account:
        {res["address"]}

        By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.

        URI: https://app.hyperunit.xyz
        Version: 1
        Chain ID: 1
        Nonce: {res["nonce"]}
        Issued At: {cat}
        Resources:
        - https://privy.io
        """

        txt = textwrap.dedent(txt).strip()
        msg = encode_defunct(text=txt)
        sig = acc.sign_message(msg)

        rep = clt.post(
            "https://auth.privy.io/api/v1/siwe/authenticate",
            headers=hdr,
            json={
                "message": txt,
                "signature": f"0x{sig.signature.hex()}",
                "chainId": "eip155:1",
                "walletClientType": "rabby_wallet",
                "connectorType": "injected",
                "mode": "login-or-sign-up",
            },
        )

        logger.debug(f"sign_hyperunit auth: {rep.status_code} {rep.text}")
        rep.raise_for_status()

        res = rep.json()
        if res["user"]["has_accepted_terms"]:
            return True

        rep = clt.post(
            "https://auth.privy.io/api/v1/users/me/accept_terms",
            headers={**hdr, "authorization": f"Bearer {res['token']}"},
            json={},
        )

        logger.debug(f"sign_hyperunit accept_terms: {rep.status_code} {rep.text}")
        rep.raise_for_status()
        return True

    @classmethod
    def get_dep_addr(cls, acc: LocalAccount, fchain: str, tchain: str, asset: str):
        fchain, tchain, asset = fchain.lower(), tchain.lower(), asset.lower()

        allowed_chains = ("hyperliquid", "ethereum", "bitcoin", "solana")
        assert fchain in allowed_chains, f"Unsupported from chain: {fchain}"
        assert tchain in allowed_chains, f"Unsupported to chain: {tchain}"

        clt = cls.mk_clt(acc.address)
        rep = clt.get(f"https://api.hyperunit.xyz/gen/{fchain}/{tchain}/{asset}/{acc.address}")
        rep.raise_for_status()

        res = rep.json()
        assert res["status"] == "OK", f"Unit deposit address fetch failed: {res}"
        dep_addr = to_addr(Web3(), res["address"])
        return str(dep_addr)

    @classmethod
    def get_ops(cls, acc: LocalAccount) -> dict:
        clt = cls.mk_clt(acc.address)
        url = f"https://api.hyperunit.xyz/operations/{acc.address}"
        rep = clt.get(url)
        rep.raise_for_status()
        return rep.json()["operations"]

    @classmethod
    def wait_ongoing_ops(cls, acc: LocalAccount, expect_ops: int):
        def _check_all_done():
            ops = cls.get_ops(acc)
            assert len(ops) >= expect_ops, "Unit task not appeared yet"

            ongoing = [x for x in ops if x.get("state") not in ("done",)]
            assert len(ongoing) == 0, f"Unit operations still ongoing: {len(ongoing)}"
            return True

        while True:
            try:
                return _check_all_done()
            except AssertionError as e:
                logger.debug(f"unit_wait_ongoing err {type(e)}: {e}")
                # time.sleep(random.uniform(5, 10))
                time.sleep(15)

    @classmethod
    def widthdraw(cls, acc: LocalAccount, token: str, amount: float):
        assert ":" in token, "Token must be in format SYMBOL:contract_address"
        clt = cls.mk_clt(acc.address)
        uts = int(time.time() * 1000)

        # todo: right now only UETH supported
        token_name = token.split(":")[0].lower()
        assert token_name == "ueth", f"Only UETH withdrawals supported, got {token_name}"

        dep_addr = cls.get_dep_addr(acc, "hyperliquid", "ethereum", "eth")

        msg = {
            "signatureChainId": "0x1",
            "hyperliquidChain": "Mainnet",
            "destination": dep_addr,
            "token": token,
            "amount": str(amount),
            "time": uts,
        }

        pld = user_signed_payload(
            "HyperliquidTransaction:SpotSend",
            [
                {"name": "hyperliquidChain", "type": "string"},
                {"name": "destination", "type": "string"},
                {"name": "token", "type": "string"},
                {"name": "amount", "type": "string"},
                {"name": "time", "type": "uint64"},
            ],
            msg,
        )

        sig = acc.sign_message(encode_typed_data(full_message=pld))
        pld = {
            "action": {"type": "spotSend", **msg},
            "nonce": uts,
            "signature": {"r": f"0x{sig.r:064x}", "s": f"0x{sig.s:064x}", "v": sig.v},
        }

        rep = clt.post("https://api.hyperliquid.xyz/exchange", json=pld)
        rep.raise_for_status()

        res = rep.json()
        assert res["status"] == "ok", f"Unit withdraw failed: {rep.text}"


# https://app.hypurr.fi/
class Hypurr:
    @classmethod
    def supply(cls, w3: Web3, ac: LocalAccount, caddr: str, amount: int) -> str:
        caddr = to_addr(w3, caddr)
        Erc20.check_approve(w3, ac, caddr, HYPURR_FI, amount)

        fn = {
            "name": "supply",
            "type": "function",
            "constant": False,
            "inputs": [
                {"name": "asset", "type": "address"},
                {"name": "amount", "type": "uint256"},
                {"name": "on_behalf_of", "type": "address"},
                {"name": "referral_code", "type": "uint16"},
            ],
            "outputs": [],
        }

        hypurr = w3.eth.contract(address=to_addr(w3, HYPURR_FI), abi=[fn])
        rs = evm_call(w3, ac, hypurr.functions.supply(caddr, amount, ac.address, 0))
        logger.debug(f"hypurr_supply: {json.dumps(rs)}")
        return rs

    @classmethod
    def get_account_data(cls, w3: Web3, user_addr: str) -> dict:
        user_addr = to_addr(w3, user_addr)

        fn = {
            "name": "getUserAccountData",
            "type": "function",
            "constant": True,
            "inputs": [{"name": "user", "type": "address"}],
            "outputs": [
                {"name": "totalCollateralBase", "type": "uint256"},
                {"name": "totalDebtBase", "type": "uint256"},
                {"name": "availableBorrowsBase", "type": "uint256"},
                {"name": "currentLiquidationThreshold", "type": "uint256"},
                {"name": "ltv", "type": "uint256"},
                {"name": "healthFactor", "type": "uint256"},
            ],
        }

        pool = w3.eth.contract(address=to_addr(w3, HYPURR_FI), abi=[fn])
        result = pool.functions.getUserAccountData(user_addr).call()

        return {
            "totalCollateral": result[0],
            "totalDebt": result[1],
            "availableBorrows": result[2],
            "liquidationThreshold": result[3],
            "ltv": result[4],
            "healthFactor": result[5],
        }

    @classmethod
    def get_safe_bal(cls, w3: Web3, ac: LocalAccount, ltv_rate: float) -> float:
        dat = Hypurr.get_account_data(w3, ac.address)
        decimals = 10**8  # USD-like token

        all_bal = dat["totalCollateral"] / decimals
        can_bal = dat["availableBorrows"] / decimals
        max_ltv = dat["availableBorrows"] / dat["totalCollateral"]
        safe_ltv = max_ltv * ltv_rate
        safe_bal = all_bal * safe_ltv
        logger.info(f"Borrow rates {max_ltv=:.2%} {safe_ltv=:.2%}")
        logger.info(f"Borrow collateral {all_bal=:.2f} {can_bal=:.2f} {safe_bal=:.2f}")
        return safe_bal

    @classmethod
    def borrow(cls, w3: Web3, ac: LocalAccount, caddr: str, amount: int) -> str:
        caddr = to_addr(w3, caddr)
        # Erc20.check_approve(w3, ac, caddr, caddr, amount)

        fn = {
            "name": "borrow",
            "type": "function",
            "constant": False,
            "inputs": [
                {"name": "asset", "type": "address"},
                {"name": "amount", "type": "uint256"},
                {"name": "interest_rate_mode", "type": "uint256"},
                {"name": "referral_code", "type": "uint16"},
                {"name": "on_behalf_of", "type": "address"},
            ],
            "outputs": [],
        }

        hypurr = w3.eth.contract(address=to_addr(w3, HYPURR_FI), abi=[fn])
        rs = evm_call(w3, ac, hypurr.functions.borrow(caddr, amount, 2, 0, ac.address))
        logger.debug(f"hypurr_borrow: {json.dumps(rs)}")
        return rs

    @classmethod
    def repay(cls, w3: Web3, ac: LocalAccount, caddr: str, amount: int) -> str:
        caddr = to_addr(w3, caddr)
        Erc20.check_approve(w3, ac, caddr, HYPURR_FI, amount)

        fn = {
            "name": "repay",
            "type": "function",
            "constant": False,
            "inputs": [
                {"name": "asset", "type": "address"},
                {"name": "amount", "type": "uint256"},
                {"name": "interest_rate_mode", "type": "uint256"},
                {"name": "on_behalf_of", "type": "address"},
            ],
            "outputs": [{"name": "", "type": "uint256"}],
        }

        hypurr = w3.eth.contract(address=to_addr(w3, HYPURR_FI), abi=[fn])
        rs = evm_call(w3, ac, hypurr.functions.repay(caddr, amount, 2, ac.address))
        logger.debug(f"hypurr_repay: {json.dumps(rs)}")
        return rs

    @classmethod
    def withdraw(cls, w3: Web3, ac: LocalAccount, caddr: str, amount: int) -> str:
        caddr = to_addr(w3, caddr)
        # Erc20.check_approve(w3, ac, caddr, HYPURR_FI, amount)

        fn = {
            "name": "withdraw",
            "type": "function",
            "constant": False,
            "inputs": [
                {"name": "asset", "type": "address"},
                {"name": "amount", "type": "uint256"},
                {"name": "to", "type": "address"},
            ],
        }

        hypurr = w3.eth.contract(address=to_addr(w3, HYPURR_FI), abi=[fn])
        rs = evm_call(w3, ac, hypurr.functions.withdraw(caddr, amount, ac.address))
        logger.debug(f"hypurr_withdraw: {json.dumps(rs)}")
        return rs

    @classmethod
    def swap(cls, w3: Web3, ac: LocalAccount, src_token: str, dst_token: str, amount: int):
        src_token = to_addr(w3, src_token)
        dst_token = to_addr(w3, dst_token)

        pld = {
            "inputToken": str(src_token),
            "outputToken": str(dst_token),
            "inputAmount": str(amount),
            "userAddress": str(ac.address),
            "outputReceiver": str(ac.address),
            "chainID": "hyperevm",
            "uniquePID": "657a8d5a95d73a70a4b49319544a42ad61d689c83679fcfe6b80e8e9b51cfe2c",
            "surgeProtection": True,
            "activateSurplusFee": True,
            "partnerAddress": "0xe5FE403dB2577B05678a11cEea4a6f89FD15E304",
            "partnerFee": 25,
        }

        clt = CltManager.create(ac.address)
        rep = clt.post(
            "https://router.gluex.xyz/v1/quote",
            headers={
                "x-api-key": "SVQkMIOLo9O2NpA0xI0pQGPV1FYIYXmk",
                "origin": "https://app.hypurr.fi",
                "referer": "https://app.hypurr.fi/swap",
            },
            json=pld,
        )

        # logger.debug(f"gluex_swap: {rep.status_code} {rep.text}")
        rep.raise_for_status()

        res = rep.json()
        assert "statusCode" in res and "result" in res, f"GlueX swap quote failed: {res}"
        assert res["statusCode"] == 200, f"GlueX swap quote failed: {res}"
        res = res["result"]

        amount1 = float(res["inputAmountUSD"])
        amount2 = float(res["outputAmountUSD"])
        price_impact = 1 - (amount2 / amount1)
        logger.debug(f"price impact: {price_impact:.3%} ({amount1:.3f} -> {amount2:.3f} in USD)")
        if price_impact > DEFAULT_SLIPPAGE:
            raise SlippageError(f"Price impact too high: {price_impact:.3%}")

        Erc20.check_approve(w3, ac, src_token, res["router"], int(res["inputAmount"]))

        params = {
            "to": to_addr(w3, res["router"]),
            "data": res["calldata"],
            "gas": int(res["computationUnits"]),
        }

        return evm_call(w3, ac, params)


# https://app.valantis.xyz/
class Valantis:
    @classmethod
    def mk_clt(cls, addr: str):
        hdr = {"origin": "https://app.valantis.xyz", "referer": "https://app.valantis.xyz/"}
        return CltManager.create(addr, hdr)

    @classmethod
    def swap(cls, w3: Web3, ac: LocalAccount, src_token: str, dst_token: str, amount: int):
        raise NotImplementedError("Valantis changed API, use different DEX for now")

        src_token = to_addr(w3, src_token)
        dst_token = to_addr(w3, dst_token)

        pld = {
            "inputToken": str(src_token),
            "outputToken": str(dst_token),
            "inputAmount": str(amount),
            "userAddress": str(ac.address),
            "outputReceiver": str(ac.address),
            "chainID": "hyperevm",
            "isPermit2": False,
        }

        clt = cls.mk_clt(ac.address)
        rep = clt.post(
            "https://analytics-v3.valantis-analytics.xyz/gluex_quote_with_surplus",
            headers={"authorization": "Bearer f2ffd7876ec03f1f4a04ed88402b1802"},
            json=pld,
        )
        rep.raise_for_status()

        res = rep.json()
        assert "statusCode" in res and "result" in res, f"GlueX swap quote failed: {res}"
        assert res["statusCode"] == 200, f"GlueX swap quote failed: {res}"
        logger.debug(f"valantis_swap: {json.dumps(res)}")
        res = res["result"]

        assert "calldata" in res and "router" in res, f"Valantis swap quote failed: {res}"

        # for example: "0.000443%"
        price_impact = float(res["averagePriceImpact"].replace("%", "")) / 100.0
        if price_impact > DEFAULT_SLIPPAGE:
            raise SlippageError(f"Price impact too high: {price_impact:.3%}")

        Erc20.check_approve(w3, ac, src_token, res["router"], int(res["inputAmount"]))

        params = {
            "to": to_addr(w3, res["router"]),
            "data": res["calldata"],
            "gas": int(res["computationUnits"]),
        }

        return evm_call(w3, ac, params)

    @classmethod
    def prices(cls):
        pld = {
            "chainId": 999,
            "addresses": [
                "0x0000000000000000000000000000000000000000",
                "0x5555555555555555555555555555555555555555",
                "0xfFaa4a3D97fE9107Cef8a3F48c069F577Ff76cC1",
                "0xfD739d4e423301CE9385c1fb8850539D657C296D",
                "0x39694eFF3b02248929120c73F90347013Aec834d",
                "0xbf747D2959F03332dbd25249dB6f00F62c6Cb526",
                "0x442bCc0798D7a10f9C14C49477ac212f1E3a2732",
                "0x5748ae796AE46A4F1348a1693de4b50560485562",
                "0x96C6cBB6251Ee1c257b2162ca0f39AA5Fa44B1FB",
                "0xca79db4B49f608eF54a5CB813FbEd3a6387bC645",
                "0xB5fE77d323d69eB352A02006eA8ecC38D882620C",
                "0x9FDBdA0A5e284c32744D2f17Ee5c74B284993463",
                "0xBe6727B535545C67d5cAa73dEa54865B92CF7907",
                "0x068f321Fa8Fb9f0D135f290Ef6a3e2813e1c8A29",
                "0x27eC642013bcB3D80CA3706599D3cdA04F6f4452",
                "0x3B4575E689DEd21CAAD31d64C4df1f10F3B2CedF",
                "0xB8CE59FC3717ada4C02eaDF9682A9e934F625ebb",
                "0x02c6a2fA58cC01A18B8D9E00eA48d65E4dF26c70",
                "0x5d3a1Ff2b6BAb83b63cd9AD0787074081a52ef34",
                "0xb50A96253aBDF803D85efcDce07Ad8becBc52BD5",
                "0x5e105266db42f78FA814322Bce7f388B4C2e61eb",
                "0x211Cc4DD073734dA055fbF44a2b4667d5E5fE5d2",
                "0x1359b05241cA5076c9F59605214f4F84114c0dE8",
                "0x9b498C3c8A0b8CD8BA1D9851d40D186F1872b44E",
                "0x47bb061C0204Af921F43DC73C7D7768d2672DdEE",
                "0x1bEe6762F0B522c606DC2Ffb106C0BB391b2E309",
                "0x52e444545fbE9E5972a7A371299522f7871aec1F",
                "0x11735dBd0B97CfA7Accf47d005673BA185f7fd49",
                "0xB09158c8297ACee00b900Dc1f8715Df46B7246a6",
                "0xdAbB040c428436d41CECd0Fb06bCFDBAaD3a9AA8",
                "0xB6b636627bccec61f24d1d3EB430397774c304FC",
                "0x7DCfFCb06B40344eecED2d1Cbf096B299fE4b405",
                "0x7280CC1f369ab574c35cb8a8D0885e9486e3B733",
                "0x6E0F6a71a74fAD5D0ED5A34b468203A4a4437b71",
                "0xFE69bc93B936B34D371defa873686C116C8488c2",
                "0xE6829d9a7eE3040e1276Fa75293Bde931859e8fA",
                "0x00fDBc53719604D924226215bc871D55e40a1009",
            ],
        }

        clt = cls.mk_clt("none")
        url = "https://analytics-v3.valantis-analytics.xyz/usd_price"
        rep = clt.post(
            url,
            json=pld,
            headers={"authorization": "Bearer f2ffd7876ec03f1f4a04ed88402b1802"},
        )
        rep.raise_for_status()
        # print(rep.status_code, rep.text), exit(-1)

        res = rep.json()
        return {x["address"].lower(): float(x["price"]) for x in res}


class Harmonix:
    @classmethod
    def mk_clt(cls, addr: str):
        hdr = {
            "origin": "https://app.harmonix.fi",
            "referer": "https://app.harmonix.fi/",
            "x-client-id": "harmonix",
        }
        return CltManager.create(addr, hdr)

    @classmethod
    def swap(cls, w3: Web3, ac: LocalAccount, src_token: str, dst_token: str, amount: int):
        clt = cls.mk_clt(ac.address)
        amount = int(amount)  # as native integer (dec * decimals)

        rep = clt.get(
            "https://aggregator-api.kyberswap.com/hyperevm/api/v1/routes",
            params={
                "tokenIn": src_token,
                "tokenOut": dst_token,
                "saveGas": False,
                "gasInclude": True,
                "amountIn": amount,
                "chargeFeeBy": "currency_in",
                "feeAmount": 1,
                "isInBps": True,
                "feeReceiver": "0x51e282383df1f745fe6fd4d26ccb0b62d337813b",
            },
        )

        rep.raise_for_status()
        res = rep.json()
        assert "code" in res and "data" in res, f"Harmonix swap quote failed: {res}"
        assert res["code"] == 0, f"Harmonix swap error code: {res}"
        res = res["data"]

        amount1 = float(res["routeSummary"]["amountInUsd"])
        amount2 = float(res["routeSummary"]["amountOutUsd"])
        price_impact = 1 - (amount2 / amount1)
        logger.debug(f"price impact: {price_impact:.3%} ({amount1:.3f} -> {amount2:.3f} in USD)")
        if price_impact > DEFAULT_SLIPPAGE:
            raise SlippageError(f"Price impact too high: {price_impact:.3%}")

        Erc20.check_approve(w3, ac, src_token, res["routerAddress"], amount)

        rep = clt.post(
            "https://aggregator-api.kyberswap.com/hyperevm/api/v1/route/build",
            json={
                "deadline": int(time.time()) + 2 * 60,
                "recipient": ac.address,
                "sender": ac.address,
                "slippageTolerance": int(DEFAULT_SLIPPAGE * 10000),
                "source": "harmonix",
                "routeSummary": res["routeSummary"],
            },
        )

        if rep.status_code != 200:
            print(rep.status_code, rep.text)
            exit(1)

        rep.raise_for_status()
        res = rep.json()
        assert "code" in res and "data" in res, f"Harmonix swap quote failed: {res}"
        assert res["code"] == 0, f"Harmonix swap error code: {res}"
        res = res["data"]

        params = {"to": res["routerAddress"], "data": res["data"], "gas": int(res["gas"])}
        return evm_call(w3, ac, params)


class Hyperliquid:
    @classmethod
    def mk_clt(cls, addr: str):
        hdr = {"origin": "https://app.hyperliquid.xyz", "referer": "https://app.hyperliquid.xyz/"}
        return CltManager.create(addr, hdr)

    @classmethod
    def sign_terms(cls, acc: LocalAccount) -> bool:
        clt = cls.mk_clt(acc.address)

        # hl randomly can answer false
        url = "https://api-ui.hyperliquid.xyz/info"
        rep = clt.post(url, json={"type": "legalCheck", "user": str(acc.address)})
        logger.debug(f"hl_legal_sign check: {rep.status_code} {rep.text}")
        rep.raise_for_status()

        res = rep.json()
        assert res["ipAllowed"], "IP not allowed"
        assert res["userAllowed"], "User not allowed"
        if res["acceptedTerms"]:
            return True

        uts = int(time.time() * 1000)
        pld = user_signed_payload(
            "Hyperliquid:AcceptTerms",
            [{"name": "hyperliquidChain", "type": "string"}, {"name": "time", "type": "uint64"}],
            {
                "hyperliquidChain": "Mainnet",
                "time": uts,
                "type": "acceptTerms",
                "signatureChainId": "0x1",
            },
        )

        sig = acc.sign_message(encode_typed_data(full_message=pld))
        pld = {
            "signature": {"r": f"0x{sig.r:064x}", "s": f"0x{sig.s:064x}", "v": sig.v},
            "signatureChainId": "0x1",
            "time": uts,
            "type": "acceptTerms2",
            "user": str(acc.address),
        }

        rep = clt.post(url, json=pld)
        # debug_http(rep)
        logger.debug(f"hl_legal_sign: {rep.status_code} {rep.text}")
        rep.raise_for_status()
        return True


class Jumper:
    @classmethod
    def mk_clt(cls, addr: str):
        hdr = {
            "origin": "https://jumper.exchange",
            "referer": "https://jumper.exchange/",
            "x-lifi-integrator": "jumper.exchange",
            "x-lifi-sdk": "3.13.3",
            "x-lifi-widget": "3.34.2",
        }
        return CltManager.create(addr, hdr)

    @classmethod
    def bridge(
        cls, w3: Web3, ac: LocalAccount, from_chain: str, to_chain: str, token: str, amount: float
    ):
        clt = cls.mk_clt(ac.address)

        chains = {
            "arb": 42161,
            "base": 8453,
            "eth": 1,
            "hle": 999,
        }

        NULL_ADDR = "0x0000000000000000000000000000000000000000"
        mapping = {
            "eth": {
                "arb": NULL_ADDR,
                "base": NULL_ADDR,
                "eth": NULL_ADDR,
                "hle": "0xbe6727b535545c67d5caa73dea54865b92cf7907",
            }
        }

        from_chain_id = chains.get(from_chain.lower())
        to_chain_id = chains.get(to_chain.lower())
        assert from_chain_id is not None, f"Unsupported from chain: {from_chain}"
        assert to_chain_id is not None, f"Unsupported to chain: {to_chain}"
        assert from_chain_id != to_chain_id, "From and to chains must be different"

        faddr = mapping.get(token.lower(), {}).get(from_chain.lower())
        taddr = mapping.get(token.lower(), {}).get(to_chain.lower())
        assert faddr is not None, f"Unsupported from token: {token} on {from_chain}"
        assert taddr is not None, f"Unsupported to token: {token} on {to_chain}"

        url = "https://api.jumper.exchange/pipeline/v1/advanced/routes"
        pld = {
            "fromAddress": str(ac.address),
            "fromAmount": int(amount),
            "fromChainId": from_chain_id,
            "fromTokenAddress": faddr,
            "toChainId": to_chain_id,
            "toTokenAddress": taddr,
            "options": {
                "integrator": "jumper.exchange",
                "order": "CHEAPEST",
                "maxPriceImpact": 0.4,
                "allowSwitchChain": True,
                "executionType": "all",
            },
        }

        rep = clt.post(url, json=pld)
        rep.raise_for_status()

        routes = rep.json()["routes"]
        assert len(routes) > 0, "No routes found"

        for route in routes:
            est_time = 0
            for step in route["steps"]:
                est_time += step["estimate"]["executionDuration"]
            route["estimatedTime"] = est_time

        max_sec = 60 * 3  # 3 minutes
        routes = [x for x in routes if x["estimatedTime"] <= max_sec]
        routes = [x for x in routes if len(x["steps"]) == 1]
        assert len(routes) > 0, "No suitable routes found"

        est = routes[0]["steps"][0]["estimate"]
        # print(json.dumps(est)), exit(1)

        # note: this is simplified version, UI do it differently:
        # 1. approve permit2 for Infinity spending
        # 2. sign permit2 permit, merge it with res["transactionRequest"] and sent to est["permit2ProxyAddress"]
        # see: callDiamondWithPermit2 / https://github.com/gmh5225/contracts-LI.FI/blob/main/docs/Permit2Proxy.md
        # BUT option with two separate approvals also and raw swap tx also works
        if faddr != NULL_ADDR:
            amount = int(est["fromAmount"])
            if "approvalAddress" in est:
                logger.debug(f"check approve spender: {faddr} to {est['approvalAddress']}")
                Erc20.check_approve(w3, ac, faddr, est["approvalAddress"], amount)

            if "permit2Address" in est:
                logger.debug(f"check approve permit2: {faddr} to {est['permit2Address']}")
                Erc20.check_approve(w3, ac, faddr, est["permit2Address"], amount)

        url = "https://api.jumper.exchange/pipeline/v1/advanced/stepTransaction"
        rep = clt.post(url, json=routes[0]["steps"][0])
        rep.raise_for_status()
        res = rep.json()
        # print(json.dumps(res))

        # re-check time estimate
        est = res["estimate"]
        exec_time = int(est["executionDuration"])
        assert exec_time <= max_sec, f"execution time too long: {exec_time}s"

        # re-check price impact
        fbal = float(est["fromAmountUSD"])
        tbal = float(est["toAmountUSD"])
        price_impact = 1 - (tbal / fbal)
        logger.debug(f"price impact: {price_impact:.3%} ({fbal:.3f} -> {tbal:.3f} in USD)")
        if price_impact > DEFAULT_SLIPPAGE:
            raise SlippageError(f"Price impact too high: {price_impact:.3%}")

        params = res["transactionRequest"]
        logger.debug(f"tx params0: {_evm_dump_params(params)}")
        params["gas"] = int(params.get("gasLimit", 0), 16)

        for td in ["gasPrice", "gasLimit"]:
            if td in params:
                del params[td]

        return evm_call(w3, ac, params)
