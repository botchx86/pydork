# PyDork v1.0.0

```
    ____        ____             __
   / __ \__  __/ __ \____  _____/ /__
  / /_/ / / / / / / / __ \/ ___/ //_/
 / ____/ /_/ / /_/ / /_/ / /  / ,<
/_/    \__, /_____/\____/_/  /_/|_|
      /____/
```

**PyDork** is an enterprise-grade Python command-line tool for advanced Google dorking with intelligent risk scoring, change detection, powerful filtering, multiple export formats, and automated rate limiting. Perfect for security researchers, bug bounty hunters, OSINT investigators, and penetration testers.

[![GitHub](https://img.shields.io/badge/github-botchx86/pydork-blue)](https://github.com/botchx86/pydork)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.0.0-brightgreen)
![Enterprise](https://img.shields.io/badge/tier-Enterprise-purple)

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Basic Searches](#basic-searches)
  - [Filtering Results](#filtering-results)
  - [Export Formats](#export-formats)
  - [Advanced Options](#advanced-options)
- [Examples](#examples)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

### Core Functionality
- **Google Dork Searches** - Execute complex Google search queries from the command line
- **Batch Processing** - Search multiple queries from a file
- **Domain Filtering** - Filter results by specific domain names
- **Title Fetching** - Automatically retrieve page titles for results
- **Status Code Checking** - Verify URL accessibility with HTTP status codes

### Advanced Filtering
- **Keyword Exclusion** (`--exclude`) - Skip URLs containing specific keywords
- **Keyword Inclusion** (`--include`) - Only keep URLs containing specific keywords
- **Regex Filtering** (`--regex`) - Filter results using regular expressions
- **URL Length Constraints** (`--min-length`, `--max-length`) - Filter by URL length
- **Deduplication** (`--dedup`) - Remove duplicate URLs automatically

### Export Formats
- **Text** - Simple newline-separated list
- **CSV** - Spreadsheet-compatible format with metadata
- **JSON** - Structured data with comprehensive metadata
- **Markdown** - Formatted with clickable links
- **HTML** - Professional styled reports with tables and indicators

### Smart Features
- **Rate Limit Handling** - Automatic retry with exponential backoff on 429 errors
- **SQLite Logging** (`--db-log`) - Persistent database logging of all searches
- **Configuration Files** (`-c`) - Load default settings from config files
- **Customizable Delays** - Control request timing to avoid detection

### NEW: Risk Scoring (v1.1) - Enterprise Feature
- **Risk Score Calculation** (`--risk-score`) - Intelligent pattern-based scoring (1-10)
- **Severity Classification**:
  - CRITICAL (9) - Admin panels, exposed credentials, database files, configs
  - HIGH (7) - Database endpoints, APIs, upload functionality
  - MEDIUM (5) - Login/auth endpoints, test/debug areas
  - LOW (2) - Static assets and public resources
- **Pattern-Based Detection** - Identifies 40+ risk indicators
- **Risk-Sorted Results** - Automatically prioritizes high-risk findings
- **Risk Indicators in Exports** - CSV and JSON include severity and pattern matches

### NEW: Change Detection (v1.2) - Continuous Monitoring
- **Baseline Management** (`--baseline`) - Save current results as reference
- **Comparison Analysis** (`--compare`) - Detect changes against baseline
- **Delta Reporting** (`--save-diff`) - Export changes to JSON
- **Change Tracking**:
  - NEW URLs (security risk indicators)
  - REMOVED URLs (infrastructure changes)
  - UNCHANGED URLs (consistency verification)
- **Summary Statistics** - Quantified change metrics
- **Perfect for Monitoring** - Track infrastructure changes over time

## Installation

### Requirements
- Python 3.6 or higher
- pip package manager

### Steps

1. **Clone the repository:**
```bash
git clone https://github.com/botchx86/pydork.git
cd pydork
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Verify installation:**
```bash
python pydork.py --version
```

## Quick Start

### Basic Search
```bash
python pydork.py 'site:example.com inurl:login' -n 10
```

### Save Results
```bash
python pydork.py 'filetype:pdf' --csv results.csv
```

### Check URL Status
```bash
python pydork.py 'inurl:admin' --check-status --html report.html
```

### Batch Search
```bash
python pydork.py -f queries.txt --dedup --json results.json
```

## Usage

### Basic Searches

#### Single Query
```bash
python pydork.py 'your google dork query'
```

#### Multiple Queries from File
```bash
python pydork.py -f queries.txt
```
Create `queries.txt` with one query per line:
```
site:example.com
inurl:login
filetype:pdf
```

#### Limit Results
```bash
python pydork.py 'query' -n 50  # Get 50 results instead of default 10
```

#### Control Request Delay
```bash
python pydork.py 'query' --delay 5  # Wait 5 seconds between requests
```

### Filtering Results

#### Exclude Keywords
```bash
python pydork.py 'site:example.com' --exclude admin test staging
# Excludes URLs containing: admin, test, or staging
```

#### Include Keywords
```bash
python pydork.py 'site:example.com' --include login auth password
# Only keeps URLs containing: login, auth, or password
```

#### Regex Pattern Filtering
```bash
python pydork.py 'query' --regex '^\w+\.pdf$'
# Only keeps URLs matching the regex pattern
```

#### URL Length Filtering
```bash
python pydork.py 'query' --min-length 50 --max-length 150
# Only keeps URLs between 50-150 characters
```

#### Domain Filtering
```bash
python pydork.py 'inurl:admin' -d example.com
# Only keeps URLs from example.com
```

#### Remove Duplicates
```bash
python pydork.py 'query' --dedup
# Removes duplicate URLs from results
```

### Export Formats

#### Text Format (default)
```bash
python pydork.py 'query' -o results.txt
```

#### CSV Format
```bash
python pydork.py 'query' --csv results.csv
```
Includes columns: URL, Title, Domain, File Type, Timestamp

#### JSON Format
```bash
python pydork.py 'query' --json results.json
```
Includes: URL, domain, file_type, timestamp, title, status_code

#### Markdown Format
```bash
python pydork.py 'query' --markdown results.md
```
Generates clickable links with formatting

#### HTML Report
```bash
python pydork.py 'query' --html report.html
```
Generates styled table with metadata

### Advanced Options

#### Fetch Page Titles
```bash
python pydork.py 'query' --fetch-titles
# Retrieves and displays page title for each result
```

#### Check HTTP Status Codes
```bash
python pydork.py 'query' --check-status
# Verifies which URLs are accessible
```

#### Rate Limit Retries
```bash
python pydork.py 'query' --max-retries 5
# Retry up to 5 times on rate limit (default: 3)
```

#### Database Logging
```bash
python pydork.py 'query' --db-log
# Logs all searches to pydork_logs.db
```

#### Configuration File
```bash
python pydork.py 'query' -c config.ini
```

Create `config.ini`:
```ini
[DEFAULT]
delay = 3
max_retries = 5
fetch_titles = True
check_status = True
```

## Examples

### Security Researcher - Finding Exposed Admin Panels
```bash
python pydork.py 'inurl:admin' --exclude fake test staging \
  --check-status --html admin_panels.html --db-log
```

### OSINT Investigation - Company Subdomain Discovery
```bash
python pydork.py 'site:*.example.com' --dedup --csv subdomains.csv \
  --fetch-titles --check-status
```

### Penetration Testing - Find Login Pages
```bash
python pydork.py 'inurl:login OR inurl:signin OR inurl:auth' \
  --include password credential auth \
  --regex 'https://' \
  --json login_pages.json --check-status
```

### Bug Bounty - Discover File Upload Endpoints
```bash
python pydork.py 'inurl:upload OR inurl:file OR inurl:media' \
  -d target.com \
  --exclude test staging internal \
  --html upload_endpoints.html
```

### Data Collection - Extract Domain Intelligence
```bash
python pydork.py -f dorking_queries.txt \
  --dedup \
  --csv all_results.csv \
  --fetch-titles \
  --check-status \
  --db-log \
  -n 100
```

### Research - PDF Document Hunting
```bash
python pydork.py 'filetype:pdf site:example.com' \
  --min-length 20 \
  --check-status \
  --markdown pdf_files.md
```

### NEW: Risk Analysis - Identify High-Risk Exposures
```bash
python pydork.py 'inurl:admin OR inurl:phpmyadmin OR .env OR .git' \
  --risk-score \
  --csv critical_findings.csv \
  --fetch-titles
# Shows CRITICAL/HIGH severity URLs sorted by risk score
```

### NEW: Continuous Monitoring - Baseline & Compare
```bash
# First run: Save baseline
python pydork.py 'site:example.com' -n 50 --baseline baseline.json

# Later run: Check for changes
python pydork.py 'site:example.com' -n 50 --compare baseline.json \
  --save-diff changes.json --risk-score --csv current_results.csv
# Reports NEW/REMOVED/UNCHANGED URLs with risk scores
```

### NEW: Security Team - Risk-Scored Intelligence
```bash
python pydork.py -f security_dorks.txt \
  --risk-score \
  --dedup \
  --json risk_analysis.json \
  --csv risk_report.csv \
  --check-status \
  --fetch-titles \
  --db-log \
  -n 100
# Complete enterprise analysis with risk scores
```

## Configuration

### Creating a Config File

Create `pydork.conf`:
```ini
[DEFAULT]
# Request settings
delay = 2
max_retries = 3

# Feature flags
fetch_titles = True
check_status = False
dedup = True
db_log = False

# Export formats (can be overridden per run)
csv = results.csv
html = report.html
```

### Loading Configuration
```bash
python pydork.py 'query' -c pydork.conf
```

Command-line arguments override config file settings.

## Architecture

### Class Structure

**RateLimitHandler**
- Handles HTTP 429 rate limit errors
- Implements exponential backoff retry logic
- Configurable retry attempts and base delay

**DatabaseLogger**
- Creates and manages SQLite database
- Tracks search queries with timestamps
- Logs individual results with metadata
- Enables historical tracking of searches

**RiskScorer** (NEW - v1.1)
- Pattern-based security risk analysis
- 4-level severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- 40+ risk indicator patterns
- Calculates scores (1-10) for each URL
- Identifies specific risk patterns matched

**ChangeDetector** (NEW - v1.2)
- Baseline/reference result management
- URL change detection (new, removed, unchanged)
- Comparison analysis and delta reporting
- Useful for continuous monitoring
- JSON-based storage and export

### Function Organization

| Category | Functions |
|----------|-----------|
| **I/O** | `load_config()`, `fetch_metadata()`, `check_url_status()` |
| **Processing** | `filter_results()`, `deduplicate()`, `get_file_extension()` |
| **Risk Analysis** | `RiskScorer.calculate_risk_score()`, `RiskScorer.get_risk_indicators()` |
| **Change Detection** | `ChangeDetector.compare_results()`, `ChangeDetector.print_comparison()` |
| **Export** | `save_csv()`, `save_json()`, `save_markdown()`, `save_html()` |
| **Search** | `googleDork()`, `summarize_results()` |
| **CLI** | `main()` |

### Data Flow

```
User Input (CLI)
    ↓
Config Loading (if specified)
    ↓
Query Preparation
    ↓
Database Logger Init (if --db-log)
    ↓
Google Search Execution + Rate Limiting
    ↓
Per-URL Filtering (domain, keywords, regex, length)
    ↓
Status/Title Fetching (if requested)
    ↓
Database Logging (if enabled)
    ↓
Results Collection & Deduplication
    ↓
Export to Selected Format(s)
    ↓
Summary Statistics
```

## Troubleshooting

### Rate Limiting (429 Errors)

**Problem:** Getting blocked by Google with 429 errors

**Solutions:**
1. Increase delay between requests:
   ```bash
   python pydork.py 'query' --delay 5
   ```

2. Increase max retries:
   ```bash
   python pydork.py 'query' --max-retries 5
   ```

3. Run with smaller batch sizes:
   ```bash
   python pydork.py 'query' -n 5
   ```

### Connection Timeouts

**Problem:** Requests timing out

**Solutions:**
1. Increase individual request timeout (hardcoded to 5 seconds in code)
2. Check network connection
3. Try from different network/location

### Missing Page Titles

**Problem:** `--fetch-titles` returns "Metadata fetch failed"

**Solutions:**
1. Some sites block metadata fetching - this is expected
2. Check site robots.txt and headers
3. Use alternative User-Agent (modify `DEFAULT_USER_AGENT` in code)

### Database Issues

**Problem:** SQLite database errors with `--db-log`

**Solutions:**
1. Ensure write permissions in directory
2. Check disk space
3. Remove corrupted `pydork_logs.db` and restart

### Slow Performance

**Problem:** Script runs slowly

**Solutions:**
1. Reduce `--fetch-titles` usage (slows execution significantly)
2. Reduce `--check-status` usage (makes HTTP requests per result)
3. Increase `--delay` if getting rate-limited
4. Reduce `-n` to fewer results per query

## Dependencies

- **googlesearch-python** - Google search library
- **beautifulsoup4** - HTML parsing for title extraction
- **requests** - HTTP client for status checks and metadata

All included in `requirements.txt`

## Version History

### v1.0.0 (2025-12-03) - Enterprise Edition
- **Risk Scoring** (v1.1) - Intelligent pattern-based risk analysis with 4-level severity
- **Change Detection** (v1.2) - Continuous monitoring with baseline comparison
- 40+ risk indicator patterns for security analysis
- Risk-sorted results prioritizing critical findings
- Baseline/comparison workflow for infrastructure tracking
- Enhanced CSV/JSON exports with risk metadata
- RiskScorer and ChangeDetector classes

### v1.0.0 (2025-12-03)
- Major feature expansion with 14 new capabilities
- Added multiple export formats (CSV, JSON, Markdown, HTML)
- Implemented smart rate limiting with exponential backoff
- Added SQLite database logging
- Enhanced filtering system (keyword, regex, URL length)

### v0.9.1 (2025-12-03)
- Bug fixes and code quality improvements
- PEP 8 compliance, index numbering fixes
- Improved exception handling

### v0.9 (2025-12-03)
- Version flag support
- Core functionality finalized

See [CHANGELOG.md](CHANGELOG.md) for full details.

## Security Considerations

- **Rate Limiting**: Always use appropriate delays to avoid detection
- **User-Agent**: Current version uses standard browser User-Agent
- **Ethics**: Only use for authorized testing and legitimate research
- **Data Storage**: Database logging creates local SQLite file - handle carefully
- **Robots.txt**: Respect website robots.txt and terms of service

## Contributing

Contributions welcome! Areas for enhancement:
- Alternative search engines (Bing, DuckDuckGo)
- Webhook notifications
- Scheduling/automation
- API server mode
- GUI interface

## License

[MIT License](LICENSE) - See LICENSE file for details

## Disclaimer

This tool is designed for authorized security testing, OSINT research, and legitimate penetration testing only. Users are responsible for ensuring they have proper authorization before testing any systems or networks. Unauthorized access to computer systems is illegal.

---

**Created by**: Jacob (botchx86)
**Repository**: https://github.com/botchx86/pydork
**Issues**: https://github.com/botchx86/pydork/issues
