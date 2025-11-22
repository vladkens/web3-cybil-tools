# web3-cybil-tools

Minimal scripts to run actions across multiple Web3 accounts (one script = one action). Shared config lives in `_wallets.txt` (private keys) and `_proxies.txt` (optional proxies).

## Current scripts

- `hyperevm-kinetiq.py` – check eligibility for Kinetiq on HyperEVM via their terms endpoint.
- `hyperevm-route.py` – HyperEVM & Unit warm-up flow.

## How to install

```sh
# clone
git clone https://github.com/vladkens/web3-cybil-tools
cd web3-cybil-tools

# install dependencies
pip install -r requirements.txt
```

## Disclaimer

These scripts iterate over private keys and send requests to third‑party endpoints. Use at your own risk. Do not abuse rate limits or violate any service terms.

### Private key security

- Never commit real keys; keep `_wallets.txt` out of public repos.
- Prefer test or burner wallets.
- Consider storing keys encrypted and generating `_wallets.txt` at runtime.
- Rotate proxies if using `_proxies.txt`; comments (`#`) and blank lines are ignored.
