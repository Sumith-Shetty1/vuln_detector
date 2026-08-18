"""
Report generation for vulnerability scan results.

This module generates HTML and JSON reports from a list of findings,
including a summary of the scan and detailed vulnerability information.
"""

import json
import logging
from datetime import datetime
from jinja2 import Template

logger = logging.getLogger(__name__)


# HTML Report Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.95;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .summary-card h3 {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }
        
        .summary-card.high .value {
            color: #dc3545;
        }
        
        .summary-card.medium .value {
            color: #ffc107;
        }
        
        .findings {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .findings-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 2px solid #dee2e6;
        }
        
        .findings-header h2 {
            font-size: 1.5em;
            color: #333;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        th {
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #495057;
            border-bottom: 2px solid #dee2e6;
            font-size: 0.95em;
        }
        
        td {
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
        }
        
        tr:hover {
            background-color: #f9f9f9;
        }
        
        .severity {
            padding: 6px 12px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.85em;
            text-align: center;
            display: inline-block;
        }
        
        .severity.high {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        
        .severity.medium {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeaa7;
        }
        
        .vuln-type {
            font-weight: 600;
            font-size: 0.95em;
        }
        
        .vuln-type.sqli {
            color: #dc3545;
        }
        
        .vuln-type.xss {
            color: #fd7e14;
        }
        
        .url {
            word-break: break-all;
            font-size: 0.9em;
            color: #667eea;
        }
        
        .param {
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.85em;
        }
        
        .evidence {
            background: #f8f9fa;
            padding: 10px;
            border-left: 3px solid #667eea;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 150px;
            overflow-y: auto;
        }
        
        .empty {
            text-align: center;
            padding: 40px 20px;
            color: #999;
        }
        
        .empty h3 {
            font-size: 1.3em;
            margin-bottom: 10px;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
            margin-top: 30px;
        }
        
        .meta-info {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            font-size: 0.9em;
            color: #666;
            margin-bottom: 20px;
        }
        
        .meta-info p {
            margin-bottom: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Web Application Vulnerability Scan</h1>
            <p>Security Assessment Report</p>
        </div>
        
        <div class="meta-info">
            <p><strong>Target URL:</strong> <span class="url">{{ target_url }}</span></p>
            <p><strong>Scan Timestamp:</strong> {{ scan_timestamp }}</p>
            <p><strong>Total Findings:</strong> {{ total_findings }}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="value">{{ total_findings }}</div>
            </div>
            <div class="summary-card high">
                <h3>High Severity</h3>
                <div class="value">{{ high_count }}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Severity</h3>
                <div class="value">{{ medium_count }}</div>
            </div>
            <div class="summary-card">
                <h3>SQL Injection</h3>
                <div class="value">{{ sqli_count }}</div>
            </div>
            <div class="summary-card">
                <h3>XSS Vulnerabilities</h3>
                <div class="value">{{ xss_count }}</div>
            </div>
        </div>
        
        <div class="findings">
            <div class="findings-header">
                <h2>Detailed Findings</h2>
            </div>
            {% if findings %}
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Parameter</th>
                        <th>Type</th>
                        <th>Payload</th>
                        <th>Evidence</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in findings %}
                    <tr>
                        <td class="url">{{ finding.url }}</td>
                        <td><span class="param">{{ finding.param_name }}</span></td>
                        <td><span class="vuln-type {% if finding.vuln_type == 'SQLi' %}sqli{% else %}xss{% endif %}">{{ finding.vuln_type }}</span></td>
                        <td><code style="background: #f0f0f0; padding: 2px 6px; border-radius: 3px; font-family: monospace;">{{ finding.payload[:50] }}{% if finding.payload|length > 50 %}...{% endif %}</code></td>
                        <td><div class="evidence">{{ finding.evidence_snippet }}</div></td>
                        <td><span class="severity {% if finding.severity == 'High' %}high{% else %}medium{% endif %}">{{ finding.severity }}</span></td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty">
                <h3>✓ No Vulnerabilities Found</h3>
                <p>The scan completed successfully with no identified vulnerabilities.</p>
            </div>
            {% endif %}
        </div>
        
        <div class="footer">
            <p>Web Application Vulnerability Scanner v0.1.0 | Educational Tool for Authorized Testing</p>
            <p>For authorized security testing only. Do not use against systems without explicit permission.</p>
        </div>
    </div>
</body>
</html>
"""


def generate_html_report(findings, target_url, output_path):
    """
    Generate an HTML report from findings.
    
    Args:
        findings (list): List of Finding objects
        target_url (str): URL that was scanned
        output_path (str): Path to write the HTML report
    
    Returns:
        str: Path to the generated report
    """
    
    # Calculate summary statistics
    high_count = sum(1 for f in findings if f.severity == 'High')
    medium_count = sum(1 for f in findings if f.severity == 'Medium')
    sqli_count = sum(1 for f in findings if f.vuln_type == 'SQLi')
    xss_count = sum(1 for f in findings if f.vuln_type == 'XSS')
    
    # Prepare template context
    context = {
        'findings': findings,
        'target_url': target_url,
        'scan_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_findings': len(findings),
        'high_count': high_count,
        'medium_count': medium_count,
        'sqli_count': sqli_count,
        'xss_count': xss_count,
    }
    
    # Render template
    template = Template(HTML_TEMPLATE)
    html_content = template.render(context)
    
    # Write to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        logger.info(f"HTML report written to {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Failed to write HTML report: {e}")
        raise


def generate_json_report(findings, target_url, output_path):
    """
    Generate a JSON report from findings.
    
    Args:
        findings (list): List of Finding objects
        target_url (str): URL that was scanned
        output_path (str): Path to write the JSON report
    
    Returns:
        str: Path to the generated report
    """
    
    # Calculate summary statistics
    high_count = sum(1 for f in findings if f.severity == 'High')
    medium_count = sum(1 for f in findings if f.severity == 'Medium')
    sqli_count = sum(1 for f in findings if f.vuln_type == 'SQLi')
    xss_count = sum(1 for f in findings if f.vuln_type == 'XSS')
    
    # Prepare report structure
    report = {
        'metadata': {
            'target_url': target_url,
            'scan_timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'summary': {
                'high_severity': high_count,
                'medium_severity': medium_count,
                'sqli': sqli_count,
                'xss': xss_count,
            }
        },
        'findings': [finding.to_dict() for finding in findings]
    }
    
    # Write to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        logger.info(f"JSON report written to {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Failed to write JSON report: {e}")
        raise


def generate_reports(findings, target_url, output_dir):
    """
    Generate both HTML and JSON reports.
    
    Args:
        findings (list): List of Finding objects
        target_url (str): URL that was scanned
        output_dir (str): Directory to write reports
    
    Returns:
        dict: Paths to generated reports {'html': path, 'json': path}
    """
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    html_path = os.path.join(output_dir, f'vulnerability_report_{timestamp}.html')
    json_path = os.path.join(output_dir, f'vulnerability_report_{timestamp}.json')
    
    generate_html_report(findings, target_url, html_path)
    generate_json_report(findings, target_url, json_path)
    
    return {'html': html_path, 'json': json_path}
