"""
Payload injector for sending test payloads to injection points.

This module handles sending payloads to discovered injection points via GET or POST
requests, with proper error handling and timeout management.
"""

import requests
import time
import logging
from requests.exceptions import RequestException, Timeout, ConnectionError

logger = logging.getLogger(__name__)


class InjectionResult:
    """Represents the result of an injection attempt."""
    
    def __init__(self, response, response_time, error=None):
        """
        Initialize an injection result.
        
        Args:
            response (requests.Response): Response object from the injection request
            response_time (float): Time taken to receive response in seconds
            error (str): Error message if injection failed
        """
        self.response = response
        self.response_time = response_time
        self.error = error
        self.success = error is None
    
    def __repr__(self):
        status = f"status={self.response.status_code}" if self.response else "error"
        return f"InjectionResult({status}, time={self.response_time:.2f}s)"


def inject_payload(injection_point, payload, timeout=10):
    """
    Send a payload to an injection point.
    
    Args:
        injection_point: InjectionPoint object with target URL and method
        payload (str): Payload string to inject
        timeout (int): Request timeout in seconds
    
    Returns:
        InjectionResult: Result of the injection attempt
    """
    
    try:
        # Prepare request data
        if injection_point.method == 'GET':
            params = injection_point.form_data_template.copy()
            params[injection_point.param_name] = payload
            
            logger.debug(f"Injecting via GET: {injection_point.url} param={injection_point.param_name}")
            
            start_time = time.time()
            response = requests.get(
                injection_point.url,
                params=params,
                timeout=timeout,
                allow_redirects=False
            )
            response_time = time.time() - start_time
            
            return InjectionResult(response, response_time)
        
        elif injection_point.method == 'POST':
            data = injection_point.form_data_template.copy()
            data[injection_point.param_name] = payload
            
            logger.debug(f"Injecting via POST: {injection_point.url} param={injection_point.param_name}")
            
            start_time = time.time()
            response = requests.post(
                injection_point.url,
                data=data,
                timeout=timeout,
                allow_redirects=False
            )
            response_time = time.time() - start_time
            
            return InjectionResult(response, response_time)
        
        else:
            error_msg = f"Unsupported HTTP method: {injection_point.method}"
            logger.error(error_msg)
            return InjectionResult(None, 0, error=error_msg)
    
    except Timeout:
        error_msg = f"Request timeout after {timeout}s to {injection_point.url}"
        logger.warning(error_msg)
        return InjectionResult(None, timeout, error=error_msg)
    
    except ConnectionError as e:
        error_msg = f"Connection error to {injection_point.url}: {str(e)}"
        logger.warning(error_msg)
        return InjectionResult(None, 0, error=error_msg)
    
    except RequestException as e:
        error_msg = f"Request failed for {injection_point.url}: {str(e)}"
        logger.warning(error_msg)
        return InjectionResult(None, 0, error=error_msg)
    
    except Exception as e:
        error_msg = f"Unexpected error during injection to {injection_point.url}: {str(e)}"
        logger.error(error_msg)
        return InjectionResult(None, 0, error=error_msg)
