from rich import print as rprint
from rich.table import Table
from tqdm import tqdm

from delib.utils import check_ip, load_lines


def main():
    tbl = Table(box=None)
    tbl.add_column("Proxy", style="cyan", no_wrap=True)
    tbl.add_column("IP", style="green")
    tbl.add_column("Country", style="magenta")
    tbl.add_column("Status", style="red")

    for proxy in tqdm(load_lines("_proxies.txt")):
        try:
            rs = check_ip(proxy)
            tbl.add_row(proxy, rs["ip"], rs["country_code"], "OK")
        except Exception as e:
            tbl.add_row(proxy, "-", "-", f"{type(e)}: {e}")

    rprint(tbl)


if __name__ == "__main__":
    main()
