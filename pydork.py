import argparse
import time
from googlesearch import search
from bs4 import BeautifulSoup
import requests
import json

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"

ASCII_ART = """
    ____        ____             __  
   / __ \__  __/ __ \____  _____/ /__
  / /_/ / / / / / / / __ \/ ___/ //_/
 / ____/ /_/ / /_/ / /_/ / /  / ,<   
/_/    \__, /_____/\____/_/  /_/|_|  
      /____/                         
"""

def fetch_metadata(url, headers):
    try:
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No Title"
        return title
    except Exception:
        return "Metadata fetch failed"

def summarize_results(results):
    file_types = {"PDF": 0, "HTML": 0, "Other": 0}
    for result in results:
        if result.endswith(".pdf"):
            file_types["PDF"] += 1
        elif result.endswith(".html") or result.endswith(".htm"):
            file_types["HTML"] += 1
        else:
            file_types["Other"] += 1

    print("\n[+] Summary:")
    for file_type, count in file_types.items():
        print(f"{file_type}: {count} results")

def googleDork(query, num_results, delay, domain_filter=None, proxy=None, fetch_titles=False):
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    proxies = {"http": proxy, "https": proxy} if proxy else None
    results = []

    print(f"[+] Searching for: {query}")
    try:
        for idx, result in enumerate(search(query, num=num_results, stop=num_results, user_agent=DEFAULT_USER_AGENT), start=1):
            if domain_filter and domain_filter not in result:
                continue

            if fetch_titles:
                title = fetch_metadata(result, headers)
                print(f"{idx}: {result} - {title}")
            else:
                print(f"{idx}: {result}")

            results.append(result)
            time.sleep(delay)

    except Exception as e:
        print(f"[-] An error occurred: {e}")

    return results

def Main():
    print(ASCII_ART)  # Display the ASCII art at the start of the tool

    parser = argparse.ArgumentParser(
        prog="pydork",
        description="PyDork: Python Google Dorking Command-Line Tool",
        epilog="Example usage:\n  python pydork.py 'site:example.com inurl:login' -n 5",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("dork", nargs="?", help="The Google Dork query to execute")
    parser.add_argument("-f", "--file", help="Specify a file containing multiple dork queries")
    parser.add_argument("-n", "--num", type=int, default=10, help="Number of results to display (default: 10)")
    parser.add_argument("-o", "--output", help="Save the results to a specified file")
    parser.add_argument("--json-output", help="Save the results to a JSON file")
    parser.add_argument("--delay", type=int, default=2, help="Set a delay (in seconds) between requests (default: 2)")
    parser.add_argument("-d", "--domain-filter", help="Filter results to include only URLs containing a specific domain")
    parser.add_argument("--proxy", help="Route queries through a proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--fetch-titles", action="store_true", help="Fetch and display page titles with results")

    args = parser.parse_args()

    if not args.dork and not args.file:
        parser.error("You must provide a dork query or a file containing queries.")

    queries = []
    if args.file:
        try:
            with open(args.file, "r") as f:
                queries = [line.strip() for line in f.readlines()]
        except Exception as e:
            print(f"[-] Failed to read file: {e}")
            return
    else:
        queries.append(args.dork)

    all_results = []

    for query in queries:
        results = googleDork(
            query=query,
            num_results=args.num,
            delay=args.delay,
            domain_filter=args.domain_filter,
            proxy=args.proxy,
            fetch_titles=args.fetch_titles
        )
        all_results.extend(results)

    if args.output:
        try:
            with open(args.output, "w") as f:
                for result in all_results:
                    f.write(result + "\n")
            print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[-] Failed to save results: {e}")

    if args.json_output:
        try:
            with open(args.json_output, "w") as f:
                json.dump(all_results, f, indent=4)
            print(f"[+] Results saved to {args.json_output}")
        except Exception as e:
            print(f"[-] Failed to save results as JSON: {e}")

    summarize_results(all_results)

if __name__ == "__main__":
    Main()

