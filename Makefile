.PHONY: init

init:
	git update-index --assume-unchanged _cex_map.txt
	git update-index --assume-unchanged _proxies.txt
	git update-index --assume-unchanged _wallets.txt
