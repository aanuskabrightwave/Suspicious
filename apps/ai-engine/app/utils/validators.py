# AYUSH WORK AREA
# Input validation utilities for the AI Engine
# Implements CONTEXT.md: "Sanitize all inputs in the validationMiddleware"
# Provides comprehensive validation for all AI Engine inputs

import re
import base64
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
import json

def validate_url(url: str) -> bool:
    """
    Validate URL format
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    # Basic URL format check
    if not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url):
        return False
    
    # Parse URL to ensure it's well-formed
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Check for suspicious patterns
        if any(pattern in url.lower() for pattern in [
            'javascript:', 'data:text/html;base64', 'vbscript:'
        ]):
            return False
        
        # Check URL length (prevent DoS)
        if len(url) > 2048:
            return False
            
    except Exception:
        return False
    
    return True


def validate_base64_image(image_data: str) -> bool:
    """
    Validate base64-encoded image data
    
    Args:
        image_data: Base64-encoded image data
        
    Returns:
        True if valid, False otherwise
    """
    if not image_data or not isinstance(image_data, str):
        return False
    
    # Remove data URL prefix if present
    if image_data.startswith('data:'):
        try:
            image_data = image_data.split(',')[1]
        except IndexError:
            return False
    
    # Validate base64 encoding
    try:
        # Check if it's properly padded
        padding = 4 - (len(image_data) % 4)
        if padding != 0:
            image_data += '=' * padding
        
        # Decode to verify
        decoded = base64.b64decode(image_data)
        
        # Check minimum size (empty image)
        if len(decoded) < 10:
            return False
            
        # Check maximum size (prevent DoS)
        if len(decoded) > 10 * 1024 * 1024:  # 10MB limit
            return False
            
    except Exception:
        return False
    
    return True


def validate_apk_data(apk_data: str) -> bool:
    """
    Validate base64-encoded APK data
    
    Args:
        apk_data: Base64-encoded APK data
        
    Returns:
        True if valid, False otherwise
    """
    if not apk_data or not isinstance(apk_data, str):
        return False
    
    # Remove data URL prefix if present
    if apk_data.startswith('data:'):
        try:
            apk_data = apk_data.split(',')[1]
        except IndexError:
            return False
    
    # Validate base64 encoding
    try:
        # Check padding
        padding = 4 - (len(apk_data) % 4)
        if padding != 0:
            apk_data += '=' * padding
        
        # Decode to verify
        decoded = base64.b64decode(apk_data)
        
        # Check APK signature (PK header)
        if len(decoded) < 4 or decoded[:4] != b'PK\x03\x04':
            return False
        
        # Check maximum size (prevent DoS)
        if len(decoded) > 100 * 1024 * 1024:  # 100MB limit
            return False
            
    except Exception:
        return False
    
    return True


def validate_scan_request(scan_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate scan request data
    
    Args:
        scan_type: Type of scan
        data: Request data
        
    Returns:
        Validated data or error dictionary
    """
    errors = []
    
    if scan_type == "url":
        url = data.get("url")
        if not url:
            errors.append("URL is required")
        elif not validate_url(url):
            errors.append("Invalid URL format")
        
    elif scan_type in ["qr", "ocr"]:
        image = data.get("image")
        if not image:
            errors.append("Image data is required")
        elif not validate_base64_image(image):
            errors.append("Invalid image data")
    
    elif scan_type == "apk":
        apk_data = data.get("apk_data")
        if not apk_data:
            errors.append("APK data is required")
        elif not validate_apk_data(apk_data):
            errors.append("Invalid APK data")
    
    else:
        errors.append(f"Unsupported scan type: {scan_type}")
    
    if errors:
        return {"valid": False, "errors": errors}
    
    return {"valid": True, "data": data}


def validate_risk_score(score: float) -> bool:
    """
    Validate risk score is within acceptable range
    
    Args:
        score: Risk score to validate
        
    Returns:
        True if valid, False otherwise
    """
    return isinstance(score, (int, float)) and 0.0 <= score <= 1.0


def validate_category(category: str) -> bool:
    """
    Validate threat category
    
    Args:
        category: Category to validate
        
    Returns:
        True if valid, False otherwise
    """
    valid_categories = [
        "safe", "low", "medium", "high", "critical",
        "phishing", "banking_scam", "investment_scam",
        "prize_scam", "verification_scam", "urgent_action",
        "qr_phishing", "malware", "spyware", "unknown"
    ]
    
    return isinstance(category, str) and category.lower() in [cat.lower() for cat in valid_categories]


def validate_timestamp(timestamp: str) -> bool:
    """
    Validate timestamp format
    
    Args:
        timestamp: Timestamp string
        
    Returns:
        True if valid, False otherwise
    """
    if not timestamp or not isinstance(timestamp, str):
        return False
    
    try:
        datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return True
    except ValueError:
        return False


def sanitize_input_for_logging(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize input data for logging (remove sensitive fields)
    
    Args:
        data: Input data dictionary
        
    Returns:
        Sanitized data dictionary
    """
    if not isinstance(data, dict):
        return data
    
    sanitized = {}
    sensitive_keys = {'token', 'password', 'secret', 'api_key', 'access_token'}
    
    for key, value in data.items():
        # Check if key contains sensitive pattern
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_input_for_logging(value)
        else:
            sanitized[key] = value
    
    return sanitized