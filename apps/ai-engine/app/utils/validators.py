import re
import base64

# # ======================================
# # AYUSH WORK AREA
# # Validation utilities for the AI Engine
# # ======================================

def validate_url(url: str) -> bool:
    """Basic regex for URL validation"""
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def validate_base64_image(s: str) -> bool:
    """Check if string is valid base64"""
    try:
        if "base64," in s:
            s = s.split("base64,")[1]
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False
