#!/usr/bin/env python3
"""
Web Application Vulnerability Scanner - Main CLI Entrypoint

DISCLAIMER AND LEGAL NOTICE:
============================
This tool is designed EXCLUSIVELY for authorized security testing against targets
you own or have explicit written permission to test. This includes intentionally
vulnerable applications like DVWA (Damn Vulnerable Web Application) and OWASP Juice Shop
running on YOUR OWN LOCAL SYSTEMS.

UNAUTHORIZED ACCESS: Using this tool to test systems without explicit permission is
ILLEGAL and violates computer fraud and abuse laws in most jurisdictions, including
the Computer Fraud and Abuse Act (CFAA) in the United States.

PERMITTED USE CASES:
- Testing on systems you own
- Testing systems with explicit written authorization from the owner
- Educational/portfolio demonstrations against intentionally vulnerable apps
  (DVWA, OWASP Juice Shop, etc.) running locally

PROHIBITED USE CASES:
- Testing without authorization
- Testing third-party systems without permission
- Scanning production systems without explicit approval
- Any malicious or illegal use

By using this tool, you acknowledge that you understand these restrictions and
agree to use this tool only for authorized testing. The author assumes no liability
for unauthorized use or damage caused by this tool.

===================================
TECHNICAL OVERVIEW:
The scanner performs the following steps:
1. Crawl - Discover forms and injection points (up to configurable depth)
2. Inject - Send SQLi and XSS payloads to each injection point
3. Detect - Analyze responses for vulnerability signatures
4. Report - Generate HTML and JSON reports with findings

Supported Vulnerabilities (this version):
- Reflected Cross-Site Scripting (XSS)
- SQL Injection (SQLi)

NOT implemented in this version:
- CSRF detection
- Authentication bypass detection
- Sensitive data exposure detection
- Stored XSS detection
- Other OWASP Top 10 categories
"""

import argparse
import logging
import sys
import os
from urllib.parse import urljoin, urlparse

from scanner.crawler import crawl
from scanner.payloads import get_payloads_by_type
from scanner.injector import inject_payload
from scanner.detector import analyze_injection
from scanner.report import generate_reports


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print welcome banner."""
    print("""
╔════════════════════════════════════════════════════════════════╗
║     Web Application Vulnerability Scanner                     ║
║     SQL Injection & Reflected XSS Detection                   ║
║                                                                ║
║     ⚠️  AUTHORIZED TESTING ONLY ⚠️                             ║
║     Use only on systems you own or have permission to test    ║
╚════════════════════════════════════════════════════════════════╝
    """)


def validate_url(url):
    """
    Validate that URL is properly formatted.
    
    Args:
        url (str): URL to validate
    
    Returns:
        str: Validated URL
    
    Raises:
        ValueError: If URL is invalid
    """
    if not url.startswith(('http://', 'https://')):
        # Assume http://
        url = f'http://{url}'
    
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError("Invalid URL format")
    except Exception as e:
        raise ValueError(f"Failed to parse URL: {e}")
    
    return url


def run_scan(target_url, output_dir, max_depth=2, timeout=10):
    """
    Run a vulnerability scan against the target.
    
    Args:
        target_url (str): URL to scan
        output_dir (str): Directory for output reports
        max_depth (int): Maximum crawl depth
        timeout (int): Request timeout in seconds
    
    Returns:
        list: List of Finding objects
    """
    
    findings = []
    
    try:
        # Step 1: Crawl
        print("\n[*] Phase 1: Crawling for injection points...")
        injection_points = crawl(target_url, max_depth=max_depth, timeout=timeout)
        
        if not injection_points:
            logger.warning("No injection points found during crawl")
            return findings
        
        print(f"[+] Found {len(injection_points)} injection points")
        
        # Step 2: Inject & Detect
        print("\n[*] Phase 2: Testing injection points...")
        
        vulnerability_types = ['SQLi', 'XSS']
        total_tests = len(injection_points) * sum(
            len(get_payloads_by_type(vt)) for vt in vulnerability_types
        )
        test_count = 0
        
        for injection_point in injection_points:
            for vuln_type in vulnerability_types:
                payloads = get_payloads_by_type(vuln_type)
                
                for payload_idx, payload in enumerate(payloads, 1):
                    test_count += 1
                    progress = (test_count / total_tests) * 100 if total_tests > 0 else 0
                    
                    # Print progress
                    print(
                        f"    [{progress:5.1f}%] Testing '{injection_point.param_name}' "
                        f"@ {injection_point.url} with {vuln_type} payload {payload_idx}/{len(payloads)}"
                    )
                    
                    # Inject payload
                    result = inject_payload(injection_point, payload, timeout=timeout)
                    
                    # Analyze response
                    if result.success:
                        finding = analyze_injection(
                            injection_point, result, payload, vuln_type
                        )
                        if finding:
                            findings.append(finding)
                            print(f"    [!] VULNERABILITY FOUND: {finding}")
        
        print(f"\n[+] Testing complete. Found {len(findings)} vulnerabilities")
        
    except KeyboardInterrupt:
        logger.error("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        raise
    
    return findings


def main():
    """Main CLI entrypoint."""
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Web Application Vulnerability Scanner - SQLi & XSS Detection',
        epilog='Use only on authorized targets. Unauthorized access is illegal.'
    )
    
    parser.add_argument(
        'target_url',
        help='Target URL to scan (e.g., http://localhost:8080 or dvwa.local)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )
    
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=2,
        help='Maximum crawl depth (default: 2)'
    )
    
    parser.add_argument(
        '-t', '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate URL
    try:
        target_url = validate_url(args.target_url)
        print(f"\n[*] Target URL: {target_url}")
    except ValueError as e:
        logger.error(f"Invalid URL: {e}")
        sys.exit(1)
    
    # Create output directory
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Output directory: {output_dir}")
    
    # Run scan
    try:
        findings = run_scan(
            target_url,
            output_dir,
            max_depth=args.depth,
            timeout=args.timeout
        )
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    # Generate reports
    print("\n[*] Phase 3: Generating reports...")
    try:
        report_paths = generate_reports(findings, target_url, output_dir)
        print(f"[+] Reports generated successfully")
        print(f"    HTML Report: {report_paths['html']}")
        print(f"    JSON Report: {report_paths['json']}")
    except Exception as e:
        logger.error(f"Failed to generate reports: {e}")
        sys.exit(1)
    
    # Print summary
    print("\n" + "="*70)
    print("SCAN SUMMARY")
    print("="*70)
    print(f"Target URL:          {target_url}")
    print(f"Total Findings:      {len(findings)}")
    
    high_count = sum(1 for f in findings if f.severity == 'High')
    medium_count = sum(1 for f in findings if f.severity == 'Medium')
    sqli_count = sum(1 for f in findings if f.vuln_type == 'SQLi')
    xss_count = sum(1 for f in findings if f.vuln_type == 'XSS')
    
    print(f"  - High Severity:   {high_count}")
    print(f"  - Medium Severity: {medium_count}")
    print(f"  - SQL Injection:   {sqli_count}")
    print(f"  - XSS:             {xss_count}")
    print("="*70)
    
    if findings:
        print("\n[!] VULNERABILITIES DETECTED - Review reports for details")
        for i, finding in enumerate(findings, 1):
            print(f"\n    [{i}] {finding.vuln_type} in parameter '{finding.param_name}'")
            print(f"        URL: {finding.url}")
            print(f"        Severity: {finding.severity}")
    else:
        print("\n[✓] No vulnerabilities found during scan")
    
    print("\n")


if __name__ == '__main__':
    main()
