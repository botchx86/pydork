# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-12-03

### Added - Risk Scoring (v1.1)
- `--risk-score` flag to calculate security risk scores for each URL
- Risk severity levels: CRITICAL (9), HIGH (7), MEDIUM (5), LOW (2)
- Pattern-based detection for:
  - CRITICAL: Admin panels, exposed credentials, database files, config files
  - HIGH: Database endpoints, API endpoints, upload functionality
  - MEDIUM: Login/auth endpoints, test/debug endpoints
  - LOW: Static assets and public resources
- Risk indicators showing which patterns match each URL
- Results sorted by risk score (highest first)
- Risk scores included in CSV and JSON exports

### Added - Change Detection (v1.2)
- `--baseline` flag to save current results as baseline for future comparison
- `--compare` flag to detect changes against baseline
- `--save-diff` flag to export comparison results to JSON
- Comparison report shows:
  - NEW URLs found since baseline
  - REMOVED URLs no longer present
  - UNCHANGED URLs (consistent)
  - Summary statistics
- Useful for continuous monitoring and infrastructure tracking

### Added - Improved Exports
- CSV exports now include Risk Score and Severity columns
- JSON exports include risk_indicators array with matching patterns
- Risk-sorted results in all formats

### Technical Improvements
- New `RiskScorer` class for pattern-based risk analysis
- New `ChangeDetector` class for baseline comparison
- Enhanced save functions with risk scoring support
- Improved CLI with new feature documentation

## [1.0.0] - 2025-12-03

### Added
- **CSV export** - Save results in CSV format with metadata
- **Deduplication** - `--dedup` flag to remove duplicate results
- **Advanced filtering**:
  - `--exclude` to skip URLs containing keywords
  - `--include` to only keep URLs with keywords
  - `--regex` to filter using regex patterns
  - `--min-length` and `--max-length` for URL length filtering
- **Rate limit handling** - Automatic retry with exponential backoff on 429 errors
- **URL status checking** - `--check-status` flag to verify URLs are live
- **Multiple export formats**:
  - HTML reports with styled tables and status codes
  - Markdown output with clickable links
  - Enhanced JSON with metadata and timestamps
- **SQLite logging** - `--db-log` flag to track all searches and results in database
- **Configuration file support** - Load defaults from `pydork.conf` or custom file
- **Enhanced metadata** - URLs now include domain extraction, file type detection, and timestamps

### Changed
- Complete rewrite with class-based architecture for better maintainability
- Improved error handling with specific exception types
- Enhanced summary statistics with per-type counts
- Better progress reporting with status codes displayed

### Technical Improvements
- Added `RateLimitHandler` class for intelligent retry logic
- Added `DatabaseLogger` class for persistent logging
- Modular export functions for each format
- Comprehensive filtering system with multiple criteria support

## [0.9.1] - 2025-12-03

### Fixed
- Fixed index numbering gaps when results are filtered by domain
- Delay now only applies to accepted results (not filtered ones)
- Improved exception handling in `fetch_metadata()` to catch only specific exceptions
- Empty query lines from file input are now filtered out
- Added validation to prevent negative delay values
- Renamed `Main()` to `main()` to follow PEP 8 conventions
- Optimized `headers` variable to only allocate when needed

## [0.9] - 2025-12-03

### Added
- `--version` flag to display the current version
- Version constant (`__version__`) in the main module

### Changed
- Improved code organization and removed unused functionality

### Removed
- Unused `--proxy` argument (proxy parameter was not functional with the google-search library)
- Unused proxy variable in `googleDork()` function

### Fixed
- Cleaned up unused parameters in function signatures

## [0.8] - Previous version
- Initial stable release with core Google Dorking functionality
- Support for multiple queries via file input
- Domain filtering
- Result exporting to text and JSON formats
- Page title fetching capability
- Custom delay between requests
