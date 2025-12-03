import argparse
import time
import re
import csv
import sqlite3
import configparser
import json
from datetime import datetime
from urllib.parse import urlparse
from pathlib import Path
from googlesearch import search
from bs4 import BeautifulSoup
import requests

__version__ = "1.0.0"

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"

# Risk scoring patterns
RISK_PATTERNS = {
    "CRITICAL": [
        r"/admin", r"/administrator", r"/wp-admin", r"/phpmyadmin",
        r"\.env", r"\.git", r"\.pem", r"\.key", r"\.sql",
        r"/config", r"web\.config", r"\.htaccess"
    ],
    "HIGH": [
        r"/database", r"/db", r"/backup", r"\.bak", r"\.old",
        r"/api", r"/api/v", r"/swagger", r"/graphql",
        r"/upload", r"/file", r"/media"
    ],
    "MEDIUM": [
        r"/login", r"/signin", r"/auth", r"/account",
        r"/user", r"/admin", r"/dashboard",
        r"/test", r"/debug", r"/console"
    ],
    "LOW": [
        r"/public", r"/static", r"/assets", r"/img", r"/images"
    ]
}

ASCII_ART = r"""
    ____        ____             __
   / __ \__  __/ __ \____  _____/ /__
  / /_/ / / / / / / / __ \/ ___/ //_/
 / ____/ /_/ / /_/ / /_/ / /  / ,<
/_/    \__, /_____/\____/_/  /_/|_|
      /____/
"""


class RateLimitHandler:
    """Handles rate limiting with exponential backoff."""

    def __init__(self, max_retries=3, base_delay=5):
        self.max_retries = max_retries
        self.base_delay = base_delay

    def retry_with_backoff(self, func, *args, **kwargs):
        for attempt in range(self.max_retries):
            try:
                return func(*args, **kwargs)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    wait_time = self.base_delay * (2 ** attempt)
                    print(f"[!] Rate limited. Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    raise
        raise Exception(f"Failed after {self.max_retries} retries")


class DatabaseLogger:
    """Logs searches and results to SQLite database."""

    def __init__(self, db_path="pydork_logs.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS searches (
                    id INTEGER PRIMARY KEY,
                    query TEXT NOT NULL,
                    num_results INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS results (
                    id INTEGER PRIMARY KEY,
                    search_id INTEGER,
                    url TEXT NOT NULL,
                    title TEXT,
                    status_code INTEGER,
                    FOREIGN KEY(search_id) REFERENCES searches(id)
                )
            """)
            conn.commit()

    def log_search(self, query, num_results):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO searches (query, num_results) VALUES (?, ?)",
                (query, num_results)
            )
            conn.commit()
            return cursor.lastrowid

    def log_result(self, search_id, url, title=None, status_code=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO results (search_id, url, title, status_code) VALUES (?, ?, ?, ?)",
                (search_id, url, title, status_code)
            )
            conn.commit()


class RiskScorer:
    """Analyzes URLs for security risks and assigns scores."""

    @staticmethod
    def calculate_risk_score(url):
        """Calculate risk score (1-10) for URL."""
        score = 1
        severity = "LOW"

        for sev_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            for pattern in RISK_PATTERNS[sev_level]:
                if re.search(pattern, url, re.IGNORECASE):
                    severity = sev_level
                    if sev_level == "CRITICAL":
                        score = max(score, 9)
                    elif sev_level == "HIGH":
                        score = max(score, 7)
                    elif sev_level == "MEDIUM":
                        score = max(score, 5)
                    else:
                        score = max(score, 2)

        return score, severity

    @staticmethod
    def get_risk_indicators(url):
        """Get specific risk indicators for a URL."""
        indicators = []
        for sev_level, patterns in RISK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    indicators.append((sev_level, pattern.replace(r"\\", "\\")))
        return indicators


class ChangeDetector:
    """Detects changes between current and baseline results."""

    def __init__(self, baseline_file="baseline.json"):
        self.baseline_file = baseline_file
        self.baseline_data = self.load_baseline()

    def load_baseline(self):
        """Load baseline results from file."""
        if Path(self.baseline_file).exists():
            try:
                with open(self.baseline_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[-] Failed to load baseline: {e}")
                return {}
        return {}

    def save_baseline(self, results):
        """Save current results as baseline."""
        try:
            baseline = {url: {"url": url, "timestamp": datetime.now().isoformat()} for url in results}
            with open(self.baseline_file, "w") as f:
                json.dump(baseline, f, indent=4)
            print(f"[+] Baseline saved to {self.baseline_file}")
        except Exception as e:
            print(f"[-] Failed to save baseline: {e}")

    def compare_results(self, current_results):
        """Compare current results with baseline."""
        baseline_urls = set(self.baseline_data.keys())
        current_urls = set(current_results)

        new_urls = current_urls - baseline_urls
        removed_urls = baseline_urls - current_urls
        unchanged_urls = current_urls & baseline_urls

        return {
            "new": list(new_urls),
            "removed": list(removed_urls),
            "unchanged": list(unchanged_urls),
            "total_new": len(new_urls),
            "total_removed": len(removed_urls),
            "total_unchanged": len(unchanged_urls)
        }

    def print_comparison(self, comparison):
        """Print comparison results."""
        print("\n[+] Change Detection Report:")
        print(f"    New URLs: {comparison['total_new']}")
        print(f"    Removed URLs: {comparison['total_removed']}")
        print(f"    Unchanged URLs: {comparison['total_unchanged']}")

        if comparison['new']:
            print("\n    [NEW] URLs found:")
            for url in comparison['new'][:10]:
                print(f"      + {url}")
            if len(comparison['new']) > 10:
                print(f"      ... and {len(comparison['new']) - 10} more")

        if comparison['removed']:
            print("\n    [REMOVED] URLs no longer found:")
            for url in comparison['removed'][:10]:
                print(f"      - {url}")
            if len(comparison['removed']) > 10:
                print(f"      ... and {len(comparison['removed']) - 10} more")


def load_config(config_file):
    """Load configuration from file."""
    config = configparser.ConfigParser()
    if Path(config_file).exists():
        config.read(config_file)
        return config
    return None


def fetch_metadata(url, headers):
    """Fetch page title from URL."""
    try:
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No Title"
        return title, response.status_code
    except (requests.RequestException, AttributeError):
        return "Metadata fetch failed", None


def check_url_status(url):
    """Check if URL is reachable and return status code."""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code
    except requests.RequestException:
        return None


def filter_results(results, exclude_keywords=None, include_keywords=None,
                   regex_pattern=None, min_length=None, max_length=None):
    """Filter results based on various criteria."""
    filtered = []

    for result in results:
        # Exclude keywords filter
        if exclude_keywords:
            if any(keyword.lower() in result.lower() for keyword in exclude_keywords):
                continue

        # Include keywords filter
        if include_keywords:
            if not any(keyword.lower() in result.lower() for keyword in include_keywords):
                continue

        # Regex filter
        if regex_pattern:
            if not re.search(regex_pattern, result):
                continue

        # URL length filter
        if min_length and len(result) < min_length:
            continue
        if max_length and len(result) > max_length:
            continue

        filtered.append(result)

    return filtered


def deduplicate(results):
    """Remove duplicate URLs."""
    seen = set()
    unique = []
    for result in results:
        if result not in seen:
            seen.add(result)
            unique.append(result)
    return unique


def get_file_extension(url):
    """Extract file extension from URL."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    if path.endswith(".pdf"):
        return "PDF"
    elif path.endswith((".html", ".htm")):
        return "HTML"
    return "Other"


def summarize_results(results):
    """Print summary statistics of results."""
    file_types = {"PDF": 0, "HTML": 0, "Other": 0}
    for result in results:
        file_type = get_file_extension(result)
        file_types[file_type] += 1

    print("\n[+] Summary:")
    print(f"Total results: {len(results)}")
    for file_type, count in file_types.items():
        print(f"  {file_type}: {count}")


def save_csv(results, filename, fetch_titles=False, risk_score=False):
    """Save results to CSV file."""
    try:
        headers_list = ["URL", "Title", "Domain", "File Type", "Timestamp"]
        if risk_score:
            headers_list.insert(1, "Risk Score")
            headers_list.insert(2, "Severity")

        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers_list)

            for result in results:
                parsed = urlparse(result)
                domain = parsed.netloc
                file_type = get_file_extension(result)
                title = ""
                score, severity = 1, "LOW"

                if fetch_titles:
                    headers = {"User-Agent": DEFAULT_USER_AGENT}
                    title, _ = fetch_metadata(result, headers)

                if risk_score:
                    score, severity = RiskScorer.calculate_risk_score(result)
                    writer.writerow([result, score, severity, title, domain, file_type, datetime.now().isoformat()])
                else:
                    writer.writerow([result, title, domain, file_type, datetime.now().isoformat()])

        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save CSV: {e}")


def save_json(results, filename, fetch_titles=False, check_status=False, risk_score=False):
    """Save results to JSON file."""
    try:
        data = []
        headers = {"User-Agent": DEFAULT_USER_AGENT}

        for result in results:
            parsed = urlparse(result)
            entry = {
                "url": result,
                "domain": parsed.netloc,
                "file_type": get_file_extension(result),
                "timestamp": datetime.now().isoformat()
            }

            if risk_score:
                score, severity = RiskScorer.calculate_risk_score(result)
                entry["risk_score"] = score
                entry["severity"] = severity
                entry["risk_indicators"] = [{"level": level, "pattern": pattern}
                                           for level, pattern in RiskScorer.get_risk_indicators(result)]

            if fetch_titles:
                title, status = fetch_metadata(result, headers)
                entry["title"] = title
                entry["status_code"] = status

            if check_status and not fetch_titles:
                status = check_url_status(result)
                entry["status_code"] = status

            data.append(entry)

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save JSON: {e}")


def save_markdown(results, filename, fetch_titles=False):
    """Save results to Markdown file."""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            f.write("# Search Results\n\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            f.write("## Results\n\n")

            headers = {"User-Agent": DEFAULT_USER_AGENT}
            for idx, result in enumerate(results, 1):
                title = ""
                if fetch_titles:
                    title, _ = fetch_metadata(result, headers)
                    f.write(f"{idx}. [{title}]({result})\n")
                else:
                    f.write(f"{idx}. [{result}]({result})\n")

        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save Markdown: {e}")


def save_html(results, filename, fetch_titles=False, check_status=False):
    """Save results to HTML report."""
    try:
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PyDork Search Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        a {{ color: #0066cc; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .status-200 {{ color: green; font-weight: bold; }}
        .status-404 {{ color: red; font-weight: bold; }}
        .summary {{ background-color: #f0f0f0; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>PyDork Search Results</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Total Results: {len(results)}</p>

    <table>
        <tr>
            <th>URL</th>
            <th>Title</th>
            <th>Domain</th>
            <th>File Type</th>
            {"<th>Status Code</th>" if check_status else ""}
        </tr>
"""

        headers = {"User-Agent": DEFAULT_USER_AGENT}
        for result in results:
            parsed = urlparse(result)
            domain = parsed.netloc
            file_type = get_file_extension(result)
            title = ""
            status_code = ""

            if fetch_titles:
                title, status = fetch_metadata(result, headers)
                if check_status and status:
                    status_code = f'<td class="status-{status}">{status}</td>'
            elif check_status:
                status = check_url_status(result)
                if status:
                    status_code = f'<td class="status-{status}">{status}</td>'

            html_content += f"""
        <tr>
            <td><a href="{result}" target="_blank">{result[:60]}...</a></td>
            <td>{title}</td>
            <td>{domain}</td>
            <td>{file_type}</td>
            {status_code}
        </tr>
"""

        html_content += """
    </table>
</body>
</html>
"""

        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save HTML: {e}")


def googleDork(query, num_results, delay, domain_filter=None, fetch_titles=False,
               exclude_keywords=None, include_keywords=None, regex_pattern=None,
               min_url_length=None, max_url_length=None, check_status=False,
               max_retries=3, db_logger=None):
    """Execute Google Dork search with advanced filtering."""
    results = []

    print(f"[+] Searching for: {query}")

    rate_limiter = RateLimitHandler(max_retries=max_retries)
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    search_id = None

    if db_logger:
        search_id = db_logger.log_search(query, num_results)

    try:
        for result in rate_limiter.retry_with_backoff(search, query, num_results=num_results):
            if domain_filter and domain_filter not in result:
                continue

            # Apply filters
            if exclude_keywords or include_keywords or regex_pattern:
                if not filter_results([result], exclude_keywords, include_keywords,
                                     regex_pattern, min_url_length, max_url_length):
                    continue

            # Check URL length
            if min_url_length and len(result) < min_url_length:
                continue
            if max_url_length and len(result) > max_url_length:
                continue

            idx = len(results) + 1
            title = ""
            status_code = None

            if fetch_titles:
                title, status_code = fetch_metadata(result, headers)
                print(f"{idx}: {result} - {title}")
                if status_code:
                    print(f"    Status: {status_code}")
            else:
                print(f"{idx}: {result}")

            if check_status and not fetch_titles:
                status_code = check_url_status(result)
                if status_code:
                    print(f"    Status: {status_code}")

            results.append(result)

            if db_logger:
                db_logger.log_result(search_id, result, title, status_code)

            time.sleep(delay)

    except Exception as e:
        print(f"[-] An error occurred: {e}")

    return results


def main():
    print(ASCII_ART)

    parser = argparse.ArgumentParser(
        prog="pydork",
        description="PyDork v1.0: Enterprise Google Dorking Tool with Risk Analysis",
        epilog="Examples:\n  python pydork.py 'site:example.com' --risk-score --csv output.csv\n  python pydork.py 'inurl:admin' --baseline baseline.json\n  python pydork.py -f queries.txt --compare baseline.json --risk-score",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Basic arguments
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("dork", nargs="?", help="The Google Dork query to execute")
    parser.add_argument("-f", "--file", help="File containing multiple dork queries (one per line)")
    parser.add_argument("-n", "--num", type=int, default=10, help="Number of results (default: 10)")
    parser.add_argument("--delay", type=int, default=2, help="Delay between requests in seconds (default: 2)")
    parser.add_argument("-c", "--config", help="Configuration file path")

    # Output formats
    parser.add_argument("-o", "--output", help="Save results to text file")
    parser.add_argument("--csv", help="Save results to CSV file")
    parser.add_argument("--json", help="Save results to JSON file")
    parser.add_argument("--markdown", help="Save results to Markdown file")
    parser.add_argument("--html", help="Save results to HTML report")

    # Filtering options
    parser.add_argument("-d", "--domain-filter", help="Filter results by domain")
    parser.add_argument("--exclude", nargs="+", help="Exclude results containing these keywords")
    parser.add_argument("--include", nargs="+", help="Include only results containing these keywords")
    parser.add_argument("--regex", help="Filter results using regex pattern")
    parser.add_argument("--min-length", type=int, help="Minimum URL length")
    parser.add_argument("--max-length", type=int, help="Maximum URL length")

    # Feature flags
    parser.add_argument("--fetch-titles", action="store_true", help="Fetch and display page titles")
    parser.add_argument("--check-status", action="store_true", help="Check HTTP status codes")
    parser.add_argument("--dedup", action="store_true", help="Remove duplicate results")
    parser.add_argument("--db-log", action="store_true", help="Log searches to SQLite database")
    parser.add_argument("--max-retries", type=int, default=3, help="Max retries on rate limit (default: 3)")

    # NEW: Risk Scoring (v1.1)
    parser.add_argument("--risk-score", action="store_true", help="Calculate risk score for each URL")

    # NEW: Change Detection (v1.2)
    parser.add_argument("--baseline", help="Save current results as baseline for comparison")
    parser.add_argument("--compare", help="Compare results against baseline file")
    parser.add_argument("--save-diff", help="Save comparison results to JSON file")

    args = parser.parse_args()

    # Validation
    if not args.dork and not args.file:
        parser.error("You must provide a dork query or a file containing queries.")

    if args.delay < 0:
        parser.error("Delay must be a non-negative integer.")

    # Load config file if provided
    if args.config:
        config = load_config(args.config)
        if config and "DEFAULT" in config:
            for key, value in config["DEFAULT"].items():
                if key not in vars(args) or getattr(args, key) is None:
                    setattr(args, key, value)

    # Prepare queries
    queries = []
    if args.file:
        try:
            with open(args.file, "r") as f:
                queries = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"[-] Failed to read file: {e}")
            return
    else:
        queries.append(args.dork)

    # Initialize database logger if requested
    db_logger = None
    if args.db_log:
        db_logger = DatabaseLogger()

    all_results = []

    # Execute searches
    for query in queries:
        results = googleDork(
            query=query,
            num_results=args.num,
            delay=args.delay,
            domain_filter=args.domain_filter,
            fetch_titles=args.fetch_titles,
            exclude_keywords=args.exclude,
            include_keywords=args.include,
            regex_pattern=args.regex,
            min_url_length=args.min_length,
            max_url_length=args.max_length,
            check_status=args.check_status,
            max_retries=args.max_retries,
            db_logger=db_logger
        )
        all_results.extend(results)

    # Deduplication
    if args.dedup:
        print(f"\n[+] Deduplicating results...")
        all_results = deduplicate(all_results)
        print(f"[+] {len(all_results)} unique results")

    # NEW: Risk Scoring (v1.1)
    if args.risk_score:
        print("\n[+] Calculating risk scores...")
        risk_results = []
        critical_count = high_count = medium_count = 0
        for result in all_results:
            score, severity = RiskScorer.calculate_risk_score(result)
            if severity == "CRITICAL":
                critical_count += 1
            elif severity == "HIGH":
                high_count += 1
            elif severity == "MEDIUM":
                medium_count += 1
            risk_results.append((result, score, severity))

        # Sort by risk score descending
        risk_results.sort(key=lambda x: x[1], reverse=True)
        print(f"    CRITICAL: {critical_count} | HIGH: {high_count} | MEDIUM: {medium_count}")
        all_results = [r[0] for r in risk_results]

    # NEW: Change Detection (v1.2)
    change_detector = None
    if args.baseline or args.compare:
        baseline_file = args.baseline or args.compare
        change_detector = ChangeDetector(baseline_file)

        if args.compare:
            comparison = change_detector.compare_results(all_results)
            change_detector.print_comparison(comparison)

            if args.save_diff:
                try:
                    with open(args.save_diff, "w") as f:
                        json.dump(comparison, f, indent=4)
                    print(f"[+] Comparison saved to {args.save_diff}")
                except Exception as e:
                    print(f"[-] Failed to save comparison: {e}")

        if args.baseline:
            change_detector.save_baseline(all_results)

    # Save in various formats
    if args.output:
        try:
            with open(args.output, "w") as f:
                for result in all_results:
                    f.write(result + "\n")
            print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"[-] Failed to save results: {e}")

    if args.csv:
        save_csv(all_results, args.csv, args.fetch_titles, args.risk_score)

    if args.json:
        save_json(all_results, args.json, args.fetch_titles, args.check_status, args.risk_score)

    if args.markdown:
        save_markdown(all_results, args.markdown, args.fetch_titles)

    if args.html:
        save_html(all_results, args.html, args.fetch_titles, args.check_status)

    summarize_results(all_results)


if __name__ == "__main__":
    main()
