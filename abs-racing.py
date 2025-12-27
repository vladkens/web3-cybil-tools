import time

from web3 import Web3

from delib import LocalAccount, evm_call, to_addr
from delib.utils import CltManager, load_lines

# https://www.gate.com/web3/activities/collect-in-the-moment-digital-collectible-with-oracle-red-bull-racing
ABSTRACT_RPC = "https://api.mainnet.abs.xyz"


def do_one(ac, w3, data):
    params = {
        "to": to_addr(w3, "0x50E78f65D325E913A3f0D1d0d0c8D7Bf7cf83e4E"),
        "data": data,
        "gas": 0xF4240,
        "maxFeePerGas": 0x3C2AD50,
        "maxPriorityFeePerGas": 0x3C2AD50,
    }

    return evm_call(w3, ac, params)


DATAS = [
    # "0xdb5398de0000000000000000000000000000000000000000000000000000000000000037",  # 55
    # "0xdb5398de000000000000000000000000000000000000000000000000000000000000003a",  # 58
    # "0xdb5398de000000000000000000000000000000000000000000000000000000000000003d",  # 61
    # "0xdb5398de0000000000000000000000000000000000000000000000000000000000000040",  # 64
    "0xdb5398de0000000000000000000000000000000000000000000000000000000000000043",  # 67
    "0xdb5398de0000000000000000000000000000000000000000000000000000000000000046",  # 70
]


def do_job(ac: LocalAccount):
    print("-" * 20)
    px = CltManager.get_proxy(ac.address)
    w3_kw = {"proxies": {"http": px, "https": px}} if px else None
    w3 = Web3(Web3.HTTPProvider(ABSTRACT_RPC, request_kwargs=w3_kw))

    bal = w3.eth.get_balance(ac.address)
    print(f"[ABS] {ac.address} balance: {w3.from_wei(bal, 'ether')} ETH")
    if bal < w3.to_wei(0.0001, "ether"):
        print(f"[ABS] {ac.address} insufficient balance, skipping...")
        return

    for data in DATAS:
        try:
            tx_hash = do_one(ac, w3, data)
            print(f"[ABS] {ac.address} sent tx: {tx_hash}")
        except Exception as e:
            print(f"[ABS] {ac.address} error {type(e)}: {e}")


def main():
    CltManager.load_proxies("_proxies.txt")
    for pk in load_lines("_wallets.txt"):
        ac = Web3().eth.account.from_key(pk)
        do_job(ac)
        time.sleep(1)


if __name__ == "__main__":
    main()
