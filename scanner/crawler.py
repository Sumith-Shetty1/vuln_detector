"""
Web crawler for discovering forms and injection points.

This module crawls a target website up to a specified depth, extracts all forms
and GET parameters from links, and returns a list of injection points that can
be tested for vulnerabilities.
"""

import requests
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)


class InjectionPoint:
    """Represents a potential injection point in the target application."""
    
    def __init__(self, url, method, param_name, form_data_template=None):
        """
        Initialize an injection point.
        
        Args:
            url (str): URL of the page containing the injection point
            method (str): HTTP method ('GET' or 'POST')
            param_name (str): Name of the parameter to inject into
            form_data_template (dict): Other form fields with default values
        """
        self.url = url
        self.method = method
        self.param_name = param_name
        self.form_data_template = form_data_template or {}
    
    def __repr__(self):
        return f"InjectionPoint(url={self.url}, method={self.method}, param={self.param_name})"


def crawl(base_url, max_depth=2, timeout=10):
    """
    Crawl a target website and discover injection points.
    
    Args:
        base_url (str): Starting URL to crawl
        max_depth (int): Maximum crawl depth (default 2)
        timeout (int): Request timeout in seconds
    
    Returns:
        list: List of InjectionPoint objects discovered during crawl
    
    Raises:
        requests.RequestException: If unable to connect to target
    """
    
    visited = set()
    injection_points = []
    to_visit = [(base_url, 0)]
    base_domain = urlparse(base_url).netloc
    
    logger.info(f"Starting crawl of {base_url} (max depth: {max_depth})")
    
    while to_visit:
        url, depth = to_visit.pop(0)
        
        # Skip if already visited or exceeded max depth
        if url in visited or depth > max_depth:
            continue
        
        visited.add(url)
        logger.debug(f"Crawling {url} (depth {depth})")
        
        try:
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            continue
        
        # Parse HTML
        try:
            soup = BeautifulSoup(response.content, 'html.parser')
        except Exception as e:
            logger.warning(f"Failed to parse {url}: {e}")
            continue
        
        # Extract forms
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            
            # Resolve relative URLs
            form_url = urljoin(url, action) if action else url
            
            # Extract input fields
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                param_name = input_field.get('name')
                if not param_name:
                    continue
                
                # Create injection point
                form_data = {}
                for inp in inputs:
                    field_name = inp.get('name')
                    if field_name:
                        # Use default/placeholder values for other fields
                        field_type = inp.get('type', 'text')
                        if field_type == 'hidden':
                            form_data[field_name] = inp.get('value', '')
                        else:
                            form_data[field_name] = 'test'
                
                injection_point = InjectionPoint(
                    url=form_url,
                    method=method,
                    param_name=param_name,
                    form_data_template=form_data
                )
                injection_points.append(injection_point)
                logger.debug(f"Found form: {method} {form_url} (param: {param_name})")
        
        # Extract GET parameters from links
        links = soup.find_all('a', href=True)
        for link in links:
            href = link.get('href')
            link_url = urljoin(url, href)
            
            # Only follow links within same domain
            if urlparse(link_url).netloc != base_domain:
                continue
            
            # Extract query parameters
            parsed = urlparse(link_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name, values in params.items():
                    if values:  # Only if param has a value
                        injection_point = InjectionPoint(
                            url=link_url,
                            method='GET',
                            param_name=param_name,
                            form_data_template={param_name: values[0]}
                        )
                        injection_points.append(injection_point)
                        logger.debug(f"Found GET param: {link_url} (param: {param_name})")
            
            # Add to visit queue if within depth limit
            if depth < max_depth and link_url not in visited:
                to_visit.append((link_url, depth + 1))
    
    logger.info(f"Crawl complete. Found {len(injection_points)} injection points")
    return injection_points
