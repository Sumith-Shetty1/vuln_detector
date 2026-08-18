# Quick Start Guide - Web Vulnerability Scanner

## Installation & Setup (30 seconds)

### Step 1: Install Dependencies
```bash
cd /workspaces/vuln_detector
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed beautifulsoup4-4.x.x jinja2-3.x.x requests-2.x.x
```

### Step 2: Verify Installation
```bash
python3 -m scanner.main --help
```

**Expected output:** Shows the CLI help menu with all options.

---

## Running Your First Scan

### Option A: Against Local DVWA (Recommended for Testing)

#### 1. Start DVWA in Docker (in Terminal 1)
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

**Wait for output showing** `DVWA is fully functional` before proceeding.

#### 2. Run Scanner Against DVWA (in Terminal 2)
```bash
cd /workspaces/vuln_detector
python3 -m scanner.main http://localhost -o ./dvwa_scan -d 2
```

**Expected output:**
```
[*] Target URL: http://localhost
[*] Output directory: ./dvwa_scan
[*] Phase 1: Crawling for injection points...
[+] Found X injection points
[*] Phase 2: Testing injection points...
    [  0.0%] Testing 'parameter_name' @ http://localhost/... with SQLi payload 1/7
    ...
[+] Found X vulnerabilities
[*] Phase 3: Generating reports...
[+] Reports generated successfully
    HTML Report: ./dvwa_scan/vulnerability_report_20240115_143022.html
    JSON Report: ./dvwa_scan/vulnerability_report_20240115_143022.json
```

#### 3. View Results
```bash
# View HTML report in browser
open ./dvwa_scan/vulnerability_report_*.html

# Or view JSON results
cat ./dvwa_scan/vulnerability_report_*.json | python3 -m json.tool
```

---

### Option B: Against OWASP Juice Shop

#### 1. Start Juice Shop in Docker (in Terminal 1)
```bash
docker run --rm -it -p 3000:3000 bkimminich/juice-shop
```

#### 2. Run Scanner (in Terminal 2)
```bash
cd /workspaces/vuln_detector
python3 -m scanner.main http://localhost:3000 -o ./juice_scan -v
```

#### 3. View Results
```bash
# Show summary in terminal
cat ./juice_scan/vulnerability_report_*.json | python3 -m json.tool | head -50

# Open HTML report
open ./juice_scan/vulnerability_report_*.html
```

---

### Option C: Against Any Local Web App

```bash
# Replace http://myapp.local with your target URL
python3 -m scanner.main http://myapp.local -o ./my_scan

# With verbose output for debugging
python3 -m scanner.main http://myapp.local -o ./my_scan -v

# With deeper crawl (3 levels instead of 2)
python3 -m scanner.main http://myapp.local -o ./my_scan -d 3

# With longer timeout (15 seconds instead of 10)
python3 -m scanner.main http://myapp.local -o ./my_scan -t 15
```

---

## Common Commands Reference

### Basic Scan
```bash
python3 -m scanner.main http://localhost:8080
```

### Scan with Custom Output Directory
```bash
python3 -m scanner.main http://localhost:8080 -o ./reports/scan_results
```

### Scan with Deeper Crawl (More Injection Points)
```bash
python3 -m scanner.main http://localhost:8080 -d 3
```

### Scan with Extended Timeout (for Slow Servers)
```bash
python3 -m scanner.main http://localhost:8080 -t 30
```

### Scan with Verbose Logging (for Debugging)
```bash
python3 -m scanner.main http://localhost:8080 -v
```

### All Options Combined
```bash
python3 -m scanner.main http://localhost:8080 \
  -o ./detailed_scan \
  -d 3 \
  -t 20 \
  -v
```

### Get Full Help
```bash
python3 -m scanner.main --help
```

---

## Understanding the Reports

### HTML Report
- **Location**: `./reports/vulnerability_report_<timestamp>.html`
- **Contains**:
  - Executive summary with statistics
  - Color-coded severity levels (Red=High/SQLi, Orange=Medium/XSS)
  - Detailed table with URL, parameter, payload, evidence snippet
  - Professional styling suitable for sharing with team

### JSON Report
- **Location**: `./reports/vulnerability_report_<timestamp>.json`
- **Structure**:
  ```json
  {
    "metadata": {
      "target_url": "http://localhost",
      "scan_timestamp": "2024-01-15T14:30:22.123456",
      "total_findings": 2,
      "summary": {
        "high_severity": 1,
        "medium_severity": 1,
        "sqli": 1,
        "xss": 1
      }
    },
    "findings": [
      {
        "url": "http://localhost/page.php",
        "param_name": "id",
        "vuln_type": "SQLi",
        "payload": "' or '1'='1",
        "evidence_snippet": "...MySQL Error...",
        "severity": "High"
      }
    ]
  }
  ```

---

## Troubleshooting

### "Connection Refused" Error
```
Error: Failed to fetch http://localhost:8080
```

**Solution**: Make sure your target is running:
```bash
curl -I http://localhost:8080
```

If it returns a response, the server is up. If not, start your target application.

### "No Injection Points Found"
```
Warning: No injection points found during crawl
```

**Possible causes**:
- Target has no forms or query parameters
- All forms are JavaScript-generated (not in HTML)
- Target requires authentication to access forms

**Solution**: 
- Try with `-d 3` for deeper crawl
- Check target URL manually in browser
- Reduce timeout with `-t 5` if pages are slow

### Slow Scan Performance
```
Scan is taking a long time...
```

**Solutions**:
- Reduce crawl depth: `-d 1`
- Reduce timeout: `-t 5`
- Reduce number of payloads in `scanner/payloads.py`

### SSL/HTTPS Certificate Errors
```
Error: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**For self-signed certificates**, edit `scanner/injector.py` line ~53:
```python
# Change from:
response = requests.get(url, timeout=timeout, allow_redirects=False)

# To:
response = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
```

---

## Example Workflow: Testing DVWA XSS Page

### 1. Start DVWA
```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

### 2. Find XSS Page
- Open http://localhost in browser
- Login with `admin` / `password`
- Navigate to: XSS (Reflected)
- Note the URL pattern

### 3. Run Scanner
```bash
python3 -m scanner.main http://localhost -o ./dvwa_test -v
```

### 4. Check Results
The scanner will:
- Crawl the DVWA homepage
- Discover the XSS form and parameters
- Inject 6 XSS payloads for each parameter
- Detect reflected XSS if payloads appear unescaped in response
- Generate reports in `./dvwa_test/`

### 5. Review Findings
```bash
# View summary in terminal
grep -A 20 "SCAN SUMMARY" /dev/null
tail -50 ./dvwa_test/vulnerability_report_*.json

# Open HTML report to see detailed evidence
open ./dvwa_test/vulnerability_report_*.html
```

---

## Module Architecture

```
┌─────────────────────────────────────┐
│         main.py (CLI)               │
│    Orchestrates pipeline            │
└────────┬────────────────────────────┘
         │
    ┌────┴─────┐
    │           │
    ▼           ▼
 crawler.py   payloads.py
  (crawl       (payload
   forms)       lists)
    │           │
    └────┬──────┘
         │
         ▼
    injector.py
    (send payloads)
         │
         ▼
    detector.py
  (check response)
         │
         ▼
    report.py
  (generate HTML/JSON)
```

---

## What to Expect

### Finding SQL Injection
```
[!] VULNERABILITY FOUND: Finding(SQLi, id @ http://localhost/page.php, severity=High)
```

### Finding Reflected XSS
```
[!] VULNERABILITY FOUND: Finding(XSS, search @ http://localhost/search.php, severity=Medium)
```

### No Vulnerabilities
```
[✓] No vulnerabilities found during scan
```

---

## For Portfolio/Learning

### Explaining the Tool
This scanner demonstrates:
- **Web Security Knowledge**: Understands SQLi and XSS attack vectors
- **Python Skills**: Multi-module project with proper error handling
- **Automation**: Orchestrates crawling, injection, detection, and reporting
- **Code Quality**: Well-documented, commented, and structured code

### Customization Examples

**Add more payloads:**
```python
# In scanner/payloads.py
SQLI_PAYLOADS.append("your_custom_payload")
```

**Add detection signature:**
```python
# In scanner/detector.py
SQL_ERROR_SIGNATURES.append(r"your_error_pattern")
```

**Customize HTML report:**
```python
# In scanner/report.py
# Edit the HTML_TEMPLATE variable
```

---

## Support & Next Steps

1. **Test against DVWA** - See it detect actual vulnerabilities
2. **Review the reports** - Understand the evidence and findings format
3. **Explore the code** - Read comments and understand each module
4. **Customize payloads** - Add your own detection signatures
5. **Use in portfolio** - Reference in your security projects

---

## Remember

⚠️ **AUTHORIZED TESTING ONLY**
- Use only on systems you own or have explicit permission to test
- DVWA and Juice Shop are intended for learning
- Never use this tool against systems without permission
- Unauthorized access is illegal

---

**Happy scanning! 🔍**
