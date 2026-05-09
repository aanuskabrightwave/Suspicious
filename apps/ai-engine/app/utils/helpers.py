# AYUSH WORK AREA
# Helper functions for the AI Engine
# Implements CONTEXT.md: "Reusable utility functions for common patterns"
# Contains functions for data processing, validation, and transformation

import re
import hashlib
import base64
import unicodedata
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime, timezone
import json

def normalize_unicode(text: str) -> str:
    """
    Normalize Unicode text to NFC form and remove common lookalikes
    
    Args:
        text: Input text
        
    Returns:
        Normalized text
    """
    # Normalize to NFC form
    normalized = unicodedata.normalize('NFC', text)
    
    # Common homograph replacements
    homograph_map = {
        'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'с': 'c', 'у': 'y',
        'А': 'A', 'Е': 'E', 'І': 'I', 'О': 'O', 'С': 'C', 'У': 'Y',
        '0': 'O', '1': 'l', '|': 'I', ' ': ' ', '‑': '-', '–': '-'
    }
    
    for char, replacement in homograph_map.items():
        normalized = normalized.replace(char, replacement)
    
    return normalized


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text using comprehensive regex
    
    Args:
        text: Text to search for URLs
        
    Returns:
        List of extracted URLs
    """
    # Comprehensive URL regex pattern
    url_pattern = r'https?://[^\s<>"\'(),\]]+'
    urls = re.findall(url_pattern, text)
    
    # Remove trailing punctuation
    cleaned_urls = []
    for url in urls:
        # Remove common trailing punctuation
        clean_url = url.rstrip('.,;:!?)')
        if clean_url != url:
            pass  # Log if needed for debugging
        cleaned_urls.append(clean_url)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for url in cleaned_urls:
        if url not in seen:
            seen.add(url)
            unique_urls.append(url)
    
    return unique_urls


def calculate_text_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text
    
    Higher entropy indicates more randomness (potential DGA domains)
    
    Args:
        text: Input text
        
    Returns:
        Entropy value (0.0 - ~4.7 for ASCII)
    """
    if not text:
        return 0.0
    
    # Calculate character frequencies
    freq = {}
    for char in text.lower():
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * (p.bit_length() - 1)  # Approximation for log2(p)
    
    return entropy


def safe_json_loads(data: str, default: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Safely load JSON data with error handling
    
    Args:
        data: JSON string to parse
        default: Default value if parsing fails
        
    Returns:
        Parsed JSON or default value
    """
    if default is None:
        default = {}
    
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        return default
    except Exception:
        return default


def hash_string(text: str, algorithm: str = 'sha256') -> str:
    """
    Hash string using specified algorithm
    
    Args:
        text: Text to hash
        algorithm: Hash algorithm ('sha256', 'md5', etc.)
        
    Returns:
        Hexadecimal hash string
    """
    hasher = getattr(hashlib, algorithm)()
    hasher.update(text.encode('utf-8'))
    return hasher.hexdigest()


def is_valid_base64(data: str) -> bool:
    """
    Validate base64 encoded string
    
    Args:
        data: Base64 string to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        # Remove data URL prefix if present
        if data.startswith('data:'):
            data = data.split(',')[1]
        
        # Check if length is multiple of 4 (padding)
        if len(data) % 4 != 0:
            # Try adding padding
            data += '=' * (4 - len(data) % 4)
        
        # Decode and re-encode to verify
        decoded = base64.b64decode(data)
        return base64.b64encode(decoded).decode('utf-8') == data.replace('=', '')
    except Exception:
        return False


def sanitize_input(text: str) -> str:
    """
    Sanitize input text to prevent injection attacks
    
    Args:
        text: Input text
        
    Returns:
        Sanitized text
    """
    if not text:
        return text
    
    # Remove control characters
    sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
    
    # Limit length to prevent DoS
    MAX_LENGTH = 10000
    if len(sanitized) > MAX_LENGTH:
        sanitized = sanitized[:MAX_LENGTH] + "...[TRUNCATED]"
    
    return sanitized


def parse_timestamp(timestamp: Union[str, float, int]) -> datetime:
    """
    Parse timestamp into datetime object
    
    Args:
        timestamp: Timestamp in various formats
        
    Returns:
        Datetime object
    """
    if isinstance(timestamp, datetime):
        return timestamp
    
    try:
        # Handle Unix timestamp
        if isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        
        # Handle ISO format
        if isinstance(timestamp, str):
            return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
    except Exception:
        pass
    
    return datetime.now(timezone.utc)


def get_domain_from_url(url: str) -> str:
    """
    Extract domain from URL
    
    Args:
        url: URL string
        
    Returns:
        Domain name
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return ""


def is_suspicious_domain(domain: str) -> bool:
    """
    Check if domain is suspicious based on patterns
    
    Args:
        domain: Domain name
        
    Returns:
        True if suspicious, False otherwise
    """
    # Check for IP address
    if re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$', domain):
        return True
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        return True
    
    # Check for excessive hyphens (common in phishing)
    if domain.count('-') > 3:
        return True
    
    # Check for homograph characters
    homograph_chars = ['а', 'е', 'і', 'о', 'с', 'ѕ', 'п', 'г']
    if any(char in domain for char in homograph_chars):
        return True
    
    return False