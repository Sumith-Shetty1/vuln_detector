"""
Vulnerability detector for analyzing injection responses.

This module analyzes HTTP responses to detect SQL Injection and Cross-Site Scripting
vulnerabilities based on known error signatures and payload reflection patterns.
"""

import logging
import re

logger = logging.getLogger(__name__)


class Finding:
    """Represents a vulnerability finding."""
    
    def __init__(self, url, param_name, vuln_type, payload, evidence_snippet, severity):
        """
        Initialize a vulnerability finding.
        
        Args:
            url (str): URL where vulnerability was found
            param_name (str): Parameter name that is vulnerable
            vuln_type (str): Type of vulnerability ('SQLi' or 'XSS')
            payload (str): Payload that triggered the vulnerability
            evidence_snippet (str): Relevant portion of response showing the vulnerability
            severity (str): Severity level ('High' or 'Medium')
        """
        self.url = url
        self.param_name = param_name
        self.vuln_type = vuln_type
        self.payload = payload
        self.evidence_snippet = evidence_snippet
        self.severity = severity
        self.timestamp = None
    
    def __repr__(self):
        return f"Finding({self.vuln_type}, {self.param_name} @ {self.url}, severity={self.severity})"
    
    def to_dict(self):
        """Convert finding to dictionary for JSON serialization."""
        return {
            'url': self.url,
            'param_name': self.param_name,
            'vuln_type': self.vuln_type,
            'payload': self.payload,
            'evidence_snippet': self.evidence_snippet,
            'severity': self.severity
        }


# SQL Error signatures to detect SQL injection
SQL_ERROR_SIGNATURES = [
    # MySQL errors
    r"mysql_fetch",
    r"mysql_num_rows",
    r"MySQL Error",
    r"You have an error in your SQL syntax",
    r"mysql_result",
    r"mysql_query",
    
    # PostgreSQL errors
    r"PostgreSQL",
    r"pg_fetch_row",
    r"pg_num_rows",
    r"Postgre SQL",
    r"psql",
    
    # MSSQL errors
    r"MSSQL",
    r"Microsoft SQL",
    r"SQL Server",
    r"Msg \d+",
    r"Level \d+",
    r"State \d+",
    
    # SQLite errors
    r"SQLite",
    r"database is locked",
    r"syntax error",
    r"near .* syntax error",
    
    # Generic SQL errors
    r"SQL syntax",
    r"SQL command",
    r"table .* doesn't exist",
    r"column .* not found",
    r"UNION ALL",
    r"UNION SELECT",
]


def detect_sqli(response_body, payload):
    """
    Detect SQL Injection by analyzing response for SQL error signatures.
    
    Args:
        response_body (str): Response body text
        payload (str): Payload that was injected
    
    Returns:
        tuple: (is_vulnerable, evidence_snippet) - is_vulnerable is bool, evidence_snippet is str or None
    """
    
    if not response_body:
        return False, None
    
    # Check for SQL error signatures (case-insensitive)
    response_lower = response_body.lower()
    
    for signature in SQL_ERROR_SIGNATURES:
        if re.search(signature, response_lower, re.IGNORECASE):
            # Extract evidence snippet around the match
            match_obj = re.search(signature, response_lower, re.IGNORECASE)
            if match_obj:
                start = max(0, match_obj.start() - 50)
                end = min(len(response_body), match_obj.end() + 50)
                evidence = response_body[start:end]
                
                logger.info(f"SQL error signature detected: {signature}")
                return True, evidence
    
    return False, None


def detect_xss(response_body, payload):
    """
    Detect Reflected XSS by checking if payload appears verbatim in response.
    
    Args:
        response_body (str): Response body text
        payload (str): Payload that was injected
    
    Returns:
        tuple: (is_vulnerable, evidence_snippet) - is_vulnerable is bool, evidence_snippet is str or None
    """
    
    if not response_body or not payload:
        return False, None
    
    # Check if payload appears unescaped in the response
    # We look for the raw payload string in the HTML
    if payload in response_body:
        # Extract evidence snippet
        idx = response_body.find(payload)
        start = max(0, idx - 50)
        end = min(len(response_body), idx + len(payload) + 50)
        evidence = response_body[start:end]
        
        logger.info(f"XSS payload reflected in response")
        return True, evidence
    
    return False, None


def analyze_injection(injection_point, injection_result, payload, vuln_type):
    """
    Analyze an injection result and create a finding if vulnerability is detected.
    
    Args:
        injection_point: InjectionPoint object
        injection_result: InjectionResult object
        payload (str): Payload that was injected
        vuln_type (str): Type of vulnerability to test ('SQLi' or 'XSS')
    
    Returns:
        Finding: Finding object if vulnerability detected, None otherwise
    """
    
    # Handle injection errors (connection failures, timeouts, etc.)
    if not injection_result.success or injection_result.response is None:
        logger.debug(f"Injection failed: {injection_result.error}")
        return None
    
    try:
        response_body = injection_result.response.text
    except Exception as e:
        logger.warning(f"Failed to decode response: {e}")
        return None
    
    # Analyze response based on vulnerability type
    is_vulnerable = False
    evidence = None
    
    if vuln_type == 'SQLi':
        is_vulnerable, evidence = detect_sqli(response_body, payload)
    elif vuln_type == 'XSS':
        is_vulnerable, evidence = detect_xss(response_body, payload)
    else:
        logger.warning(f"Unknown vulnerability type: {vuln_type}")
        return None
    
    # Create finding if vulnerability detected
    if is_vulnerable:
        severity = 'High' if vuln_type == 'SQLi' else 'Medium'
        
        finding = Finding(
            url=injection_point.url,
            param_name=injection_point.param_name,
            vuln_type=vuln_type,
            payload=payload,
            evidence_snippet=evidence,
            severity=severity
        )
        
        logger.info(f"Vulnerability found: {finding}")
        return finding
    
    return None
