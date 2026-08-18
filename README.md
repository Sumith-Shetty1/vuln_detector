# Web Application Vulnerability Scanner

An educational/portfolio security assessment tool for detecting **SQL Injection (SQLi)** and **Reflected Cross-Site Scripting (XSS)** vulnerabilities in web applications.

⚠️ **AUTHORIZED TESTING ONLY** - This tool is designed for testing intentionally vulnerable applications on YOUR OWN systems (like DVWA or OWASP Juice Shop locally). Unauthorized testing is illegal.

## Features

- **Automated Web Crawling**: Discovers forms and injection points up to configurable depth
- **SQLi Detection**: Tests for SQL Injection vulnerabilities using error-based detection
- **XSS Detection**: Tests for Reflected XSS by checking for unescaped payload reflection
- **Detailed Reporting**: Generates both HTML and JSON reports with evidence snippets
- **Live Progress**: Console output showing real-time scan progress
- **No External Scanning Libraries**: All detection logic is handwritten and transparent

## Scope & Limitations

### What This Scanner Detects
- **Reflected SQL Injection**: Error-based SQLi detection via SQL error signatures
- **Reflected XSS**: Detection of unescaped payload reflection in HTML responses

### What This Scanner Does NOT Detect (by design)
- Stored XSS (requires JavaScript execution and response tracking)
- CSRF vulnerabilities
- Authentication/Authorization bypass
- Sensitive data exposure
- Other OWASP Top 10 categories
- JavaScript-rendered content (no Selenium/Puppeteer)

## Project Structure

```
scanner/
├── __init__.py         # Package initialization with disclaimer
├── crawler.py          # Web crawler for discovering forms and parameters
├── payloads.py         # Static payload definitions for SQLi and XSS
├── injector.py         # Payload injection and request handling
├── detector.py         # Vulnerability detection and finding analysis
├── report.py           # HTML and JSON report generation
└── main.py             # CLI entrypoint and orchestration

requirements.txt        # Python dependencies
README.md              # This file
```

## Installation

### Prerequisites
- Python 3.7+
- pip (Python package manager)

### Quick Setup

1. **Clone/setup the project**:
   ```bash
   cd /path/to/vuln_detector
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Make main.py executable** (optional):
   ```bash
   chmod +x scanner/main.py
   ```

## Usage

### Basic Scan

```bash
python -m scanner.main http://localhost:8080
```

### With Custom Output Directory

```bash
python -m scanner.main http://localhost:8080 -o ./my_reports
```

### With Extended Crawl Depth

```bash
python -m scanner.main http://localhost:8080 -d 3
```

### With Verbose Logging

```bash
python -m scanner.main http://localhost:8080 -v
```

### Full Example with All Options

```bash
python -m scanner.main http://dvwa.local -o ./scan_results -d 2 -t 15 -v
```

### CLI Arguments

```
positional arguments:
  target_url            Target URL to scan (e.g., http://localhost:8080)

optional arguments:
  -h, --help            Show help message and exit
  -o, --output DIR      Output directory for reports (default: ./reports)
  -d, --depth DEPTH     Maximum crawl depth (default: 2)
  -t, --timeout SECONDS Request timeout in seconds (default: 10)
  -v, --verbose         Enable verbose logging for debugging
```

## Testing Against DVWA

### Setup DVWA Locally

1. **Using Docker** (recommended):
   ```bash
   docker run --rm -it -p 80:80 vulnerables/web-dvwa
   ```

2. **Access DVWA**:
   - Navigate to: `http://localhost`
   - Default credentials: `admin` / `password`
   - Login and navigate to "SQL Injection" or "XSS (Reflected)" practice pages

### Run Scanner Against DVWA

```bash
# Scan DVWA (unauthenticated pages)
python -m scanner.main http://localhost -o ./dvwa_scan

# Or with verbose output
python -m scanner.main http://localhost -o ./dvwa_scan -v
```

## Testing Against OWASP Juice Shop

### Setup Juice Shop Locally

1. **Using Docker**:
   ```bash
   docker run --rm -it -p 3000:3000 bkimminich/juice-shop
   ```

2. **Access Juice Shop**:
   - Navigate to: `http://localhost:3000`
   - Explore the various vulnerable endpoints

### Run Scanner Against Juice Shop

```bash
python -m scanner.main http://localhost:3000 -o ./juice_shop_scan
```

## Report Output

The scanner generates two report files in the output directory:

### HTML Report
- **File**: `vulnerability_report_<timestamp>.html`
- **Format**: Interactive HTML with styled tables and evidence snippets
- **Contains**:
  - Executive summary with statistics
  - Color-coded severity levels (High/Medium)
  - Detailed findings table with URL, parameter, payload, and evidence
  - Summary breakdown by vulnerability type

### JSON Report
- **File**: `vulnerability_report_<timestamp>.json`
- **Format**: Machine-readable JSON for integration with other tools
- **Contains**:
  - Metadata (target URL, scan timestamp, statistics)
  - Array of findings with full details

### Example Report Location
```
./reports/
├── vulnerability_report_20240115_143022.html
└── vulnerability_report_20240115_143022.json
```

## Module Details

### crawler.py
Discovers injection points by crawling the target application:
- Extracts all `<form>` elements with action URLs, methods, and input fields
- Extracts GET parameters from `<a href>` links with query strings
- Respects domain boundaries (doesn't crawl outside target domain)
- Returns `InjectionPoint` objects with URL, method, parameter name, and form template

**Key Functions**:
- `crawl(base_url, max_depth=2, timeout=10)`: Main crawler function

### payloads.py
Static payload lists for vulnerability testing:
- **SQLI_PAYLOADS**: 7 SQL injection payloads targeting various database systems
- **XSS_PAYLOADS**: 6 cross-site scripting payloads with different injection methods

**Key Functions**:
- `get_payloads_by_type(vuln_type)`: Retrieve payloads by type ('SQLi' or 'XSS')

### injector.py
Sends payloads to injection points and handles responses:
- Supports both GET and POST injection methods
- Respects form structure and parameter templates
- Includes error handling for timeouts and connection failures
- Returns `InjectionResult` with response and response time metrics

**Key Functions**:
- `inject_payload(injection_point, payload, timeout=10)`: Send a payload to injection point

### detector.py
Analyzes HTTP responses to detect vulnerabilities:
- **SQL Injection Detection**: Checks for SQL error signatures (MySQL, PostgreSQL, MSSQL, SQLite)
- **XSS Detection**: Checks if payload appears verbatim in response HTML
- Returns `Finding` objects with vulnerability details and evidence

**Key Functions**:
- `detect_sqli(response_body, payload)`: Detect SQL injection in response
- `detect_xss(response_body, payload)`: Detect reflected XSS in response
- `analyze_injection(injection_point, injection_result, payload, vuln_type)`: Full analysis pipeline

### report.py
Generates HTML and JSON reports from findings:
- **HTML Reports**: Professional styled reports with severity color-coding
- **JSON Reports**: Structured data for programmatic use
- Includes summary statistics and detailed finding evidence

**Key Functions**:
- `generate_html_report(findings, target_url, output_path)`: Generate HTML report
- `generate_json_report(findings, target_url, output_path)`: Generate JSON report
- `generate_reports(findings, target_url, output_dir)`: Generate both reports

### main.py
CLI orchestration and workflow:
- Argument parsing and validation
- Workflow coordination: Crawl → Inject → Detect → Report
- Progress tracking and console output
- Error handling and logging

**Key Functions**:
- `main()`: CLI entrypoint
- `run_scan(target_url, output_dir, max_depth, timeout)`: Execute full scan pipeline
- `validate_url(url)`: URL validation and normalization

## Example Workflow

```
1. User runs: python -m scanner.main http://localhost:8080

2. Scanner initializes and validates target URL

3. Phase 1 - Crawling:
   ✓ Discovers 12 injection points
     - 5 POST parameters from forms
     - 7 GET parameters from links

4. Phase 2 - Testing:
   ✓ Injects 7 SQLi payloads × 12 points = 84 tests
   ✓ Injects 6 XSS payloads × 12 points = 72 tests
   ! Vulnerability found: SQLi in 'username' parameter
   ! Vulnerability found: XSS in 'search' parameter
   ✓ 156 tests completed

5. Phase 3 - Reporting:
   ✓ Generated HTML report: ./reports/vulnerability_report_20240115_143022.html
   ✓ Generated JSON report: ./reports/vulnerability_report_20240115_143022.json

6. Summary:
   Total Findings: 2
   - High Severity (SQLi): 1
   - Medium Severity (XSS): 1
```

## Common Use Cases

### Portfolio Demonstration
Perfect for demonstrating AppSec knowledge in portfolio projects:
```bash
# Test against intentionally vulnerable apps
python -m scanner.main http://dvwa.local -o ./portfolio_demo -v
```

### Security Team Testing
Baseline assessment of development/staging environments:
```bash
# Scan with extended depth and logging
python -m scanner.main http://staging.internal -d 3 -v
```

### CI/CD Integration
Quick automated checks in pipeline:
```bash
# Scan with short timeout and no verbose output
python -m scanner.main http://localhost:8080 -o ./ci_reports -t 5
```

## Learning & Customization

### Extending Payload Lists
Edit `scanner/payloads.py` to add custom payloads:
```python
SQLI_PAYLOADS = [
    "' or '1'='1",
    "your_custom_payload_here",
    # ...
]
```

### Adding New Signatures
Edit `scanner/detector.py` to add detection signatures:
```python
SQL_ERROR_SIGNATURES = [
    r"mysql_fetch",
    r"your_error_signature",
    # ...
]
```

### Adjusting Report Templates
Modify the `HTML_TEMPLATE` in `scanner/report.py` to customize reports:
- Change colors, styling, or layout
- Add additional metadata or statistics
- Include custom branding

## Security Considerations

### What This Tool Does NOT Do
- ✗ Authenticate to applications (session management)
- ✗ Detect stored vulnerabilities
- ✗ Render JavaScript or interact with DOM
- ✗ Test for authentication bypass or authorization flaws
- ✗ Detect CSRF or security headers

### Safe Testing Practices
1. **Only test systems you own or have written permission to test**
2. **Inform system owners before running scans**
3. **Use timeouts to prevent resource exhaustion** (default 10s)
4. **Test in non-production environments when possible**
5. **Review findings manually before reporting**

## Troubleshooting

### Connection Refused
```
Error: Failed to fetch http://localhost:8080
```
**Solution**: Ensure target application is running and accessible:
```bash
curl -I http://localhost:8080
```

### SSL/HTTPS Errors
```
Error: [SSL: CERTIFICATE_VERIFY_FAILED]
```
**Solution**: For self-signed certificates in testing, the scanner should work with `http://` URLs. For `https://`, disable verification in `injector.py`:
```python
requests.get(url, verify=False, ...)
```

### No Injection Points Found
```
Warning: No injection points found during crawl
```
**Possible causes**:
- Target has no forms or query parameters
- Forms are JavaScript-rendered (not in HTML)
- Forms are on pages behind authentication
- Target blocks crawling attempts

### Slow Scans
**Solutions**:
- Reduce max depth: `-d 1`
- Increase timeout with care: `-t 5` (lower timeout)
- Test fewer payloads (edit `payloads.py`)

## License & Disclaimer

This tool is provided for **authorized security testing only**. By using this tool:

- You agree to use it ONLY on systems you own or have explicit written permission to test
- You acknowledge that unauthorized access is illegal
- You assume all responsibility for your use of this tool
- The author assumes no liability for unauthorized use or damage

## References

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [DVWA (Damn Vulnerable Web Application)](http://www.dvwa.co.uk/)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)

## Version

**Version**: 0.1.0  
**Status**: Educational/Portfolio Version  
**Last Updated**: 2024

---

**Remember**: This tool is for learning and authorized testing only. Always get permission before testing any system you don't own.