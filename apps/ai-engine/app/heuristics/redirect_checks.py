# AYUSH WORK AREA
# Redirect chain analysis heuristics
# Implements CONTEXT.md requirement: Detect redirect-based phishing
# Focuses on URL shorteners, redirect chains, and obfuscation techniques

import re
import logging
from typing import Dict, List, Tuple, Optional, Set
from urllib.parse import urlparse, urljoin
import requests
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("redirect_checks")

class RedirectHeuristicChecker:
    """
    Redirect chain analysis for phishing detection
    
    This class implements heuristics to detect malicious redirect patterns,
    including:
    
    1. Excessive redirect chains (common in phishing)
    2. Redirects through URL shorteners
    3. Obfuscated redirect destinations
    4. Mixed HTTP/HTTPS redirects
    
    Security Note: Redirect analysis should be performed with caution
    to avoid hitting rate limits or triggering security systems.
    This implementation uses conservative timeouts and limits.
    """
    
    def __init__(self):
        """Initialize redirect checking rules"""
        self._initialize_rules()
        self.max_redirects = 5  # Prevent infinite loops
        self.timeout = 5  # Seconds for HTTP requests
        logger.info("Redirect heuristic checker initialized")
    
    def _initialize_rules(self):
        """Initialize redirect checking rules"""
        # Known URL shorteners
        self.url_shorteners = {
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co',
            'is.gd', 'adf.ly', 'cutt.ly', 'shorte.st', 'vl.lc',
            'lnkd.in', 'buff.ly', 'rebrand.ly', 's.id'
        }
        
        # Suspicious redirect patterns
        self.suspicious_patterns = [
            # Pattern 1: Redirect to same domain with different path
            (r'https?://[^/]+/.*\?.*redirect=', 'redirect_parameter'),
            
            # Pattern 2: Base64 encoded URLs
            (r'data:text/html;base64,', 'base64_encoded'),
            
            # Pattern 3: JavaScript redirects
            (r'javascript:', 'javascript_redirect'),
            
            # Pattern 4: Meta refresh tags (in HTML content)
            (r'<meta\s+http-equiv="refresh"\s+content="\d+;\s*url=([^"]+)"', 'meta_refresh'),
            
            # Pattern 5: iframe with suspicious src
            (r'<iframe[^>]+src=["\']https?://[^"\'/]+/[^"\'/]+["\']', 'suspicious_iframe'),
        ]
        
        # Common phishing redirect destinations
        self.phishing_destinations = {
            'login', 'signin', 'account', 'verify', 'secure',
            'payment', 'checkout', 'confirm', 'update'
        }
    
    def analyze_redirect_chain(self, url: str, follow_redirects: bool = True) -> Dict[str, Any]:
        """
        Analyze a URL for redirect-based phishing indicators
        
        Args:
            url: Initial URL to analyze
            follow_redirects: Whether to follow redirects (default: True)
            
        Returns:
            Dictionary containing:
                - redirect_chain: List of URLs in the chain
                - indicators: Detected phishing indicators
                - risk_score: Calculated risk score (0.0-1.0)
                - confidence: Confidence in detection
                - details: Additional technical details
        """
        redirect_chain = [url]
        indicators = []
        total_score = 0.0
        
        try:
            if follow_redirects:
                # Follow redirects (with limit)
                current_url = url
                redirect_count = 0
                
                while redirect_count < self.max_redirects:
                    try:
                        # Make HEAD request to avoid downloading content
                        response = requests.head(
                            current_url,
                            timeout=self.timeout,
                            allow_redirects=False,
                            headers={'User-Agent': 'SentinelAI-Scanner/1.0'}
                        )
                        
                        # Check for redirect
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location')
                            if location:
                                # Resolve relative URLs
                                next_url = urljoin(current_url, location)
                                
                                # Add to chain
                                redirect_chain.append(next_url)
                                
                                # Check for suspicious patterns
                                chain_result = self._analyze_redirect_step(next_url, current_url)
                                indicators.extend(chain_result["indicators"])
                                total_score += chain_result["score"]
                                
                                current_url = next_url
                                redirect_count += 1
                            else:
                                break
                        else:
                            # No more redirects
                            break
                    except requests.exceptions.RequestException as e:
                        logger.warning(f"Redirect request failed for {current_url}: {str(e)}")
                        break
            
            # Analyze the final URL
            final_url = redirect_chain[-1]
            final_analysis = self._analyze_final_url(final_url)
            indicators.extend(final_analysis["indicators"])
            total_score += final_analysis["score"]
            
            # Calculate confidence
            confidence = min(len(indicators) * 0.2, 0.9)
            
            # Normalize risk score
            risk_score = min(total_score, 1.0)
            
            return {
                "redirect_chain": redirect_chain,
                "indicators": indicators,
                "risk_score": risk_score,
                "confidence": confidence,
                "details": {
                    "initial_url": url,
                    "final_url": final_url,
                    "redirect_count": len(redirect_chain) - 1,
                    "analysis_time": datetime.utcnow().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Redirect analysis failed for {url}: {str(e)}", exc_info=True)
            return {
                "redirect_chain": [url],
                "indicators": [{"rule": "error", "description": str(e), "severity": "high", "score": 0.5}],
                "risk_score": 0.5,
                "confidence": 0.0,
                "details": {"error": str(e)}
            }
    
    def _analyze_redirect_step(self, next_url: str, prev_url: str) -> Dict[str, Any]:
        """Analyze a single redirect step"""
        indicators = []
        score = 0.0
        
        # Check if next URL is a known shortener
        parsed = urlparse(next_url)
        domain = parsed.netloc.lower()
        
        if any(shortener in domain for shortener in self.url_shorteners):
            indicators.append({
                "rule": "url_shortener",
                "description": f"Redirect through URL shortener: {domain}",
                "severity": "medium",
                "score": 0.6
            })
            score += 0.6
        
        # Check for suspicious patterns in URL
        for pattern, rule_name in self.suspicious_patterns:
            if re.search(pattern, next_url):
                indicators.append({
                    "rule": rule_name,
                    "description": f"Suspicious pattern in redirect: {rule_name}",
                    "severity": "high",
                    "score": 0.7
                })
                score += 0.7
        
        # Check if redirect destination mimics legitimate sites
        if self._is_phishing_destination(next_url):
            indicators.append({
                "rule": "phishing_destination",
                "description": "Redirect destination mimics phishing site",
                "severity": "high",
                "score": 0.8
            })
            score += 0.8
        
        # Check for mixed HTTP/HTTPS
        if prev_url.startswith('https://') and next_url.startswith('http://'):
            indicators.append({
                "rule": "http_downgrade",
                "description": "HTTPS to HTTP downgrade in redirect chain",
                "severity": "high",
                "score": 0.7
            })
            score += 0.7
        
        return {
            "indicators": indicators,
            "score": score
        }
    
    def _analyze_final_url(self, url: str) -> Dict[str, Any]:
        """Analyze the final URL in redirect chain"""
        indicators = []
        score = 0.0
        
        # Parse URL
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check for suspicious path patterns
        suspicious_paths = [
            '/login', '/signin', '/account', '/verify', '/secure',
            '/payment', '/checkout', '/confirm', '/update'
        ]
        
        for suspicious_path in suspicious_paths:
            if suspicious_path in path:
                indicators.append({
                    "rule": "suspicious_path",
                    "description": f"Suspicious path in final URL: {suspicious_path}",
                    "severity": "medium",
                    "score": 0.5
                })
                score += 0.5
        
        # Check for query parameters that indicate redirection
        query = parsed.query.lower()
        redirect_params = ['redirect', 'url', 'next', 'return', 'goto', 'destination']
        
        for param in redirect_params:
            if param in query:
                indicators.append({
                    "rule": "redirect_param",
                    "description": f"Redirect parameter in URL: {param}",
                    "severity": "medium",
                    "score": 0.4
                })
                score += 0.4
        
        # Check if domain is suspicious
        if self._is_suspicious_domain(domain):
            indicators.append({
                "rule": "suspicious_domain",
                "description": f"Suspicious domain in final URL: {domain}",
                "severity": "high",
                "score": 0.7
            })
            score += 0.7
        
        return {
            "indicators": indicators,
            "score": score
        }
    
    def _is_phishing_destination(self, url: str) -> bool:
        """Check if URL destination mimics phishing sites"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check for common phishing patterns
        phishing_indicators = [
            'login' in domain and 'google' in domain,
            'signin' in domain and 'facebook' in domain,
            'account' in domain and 'amazon' in domain,
            'verify' in domain and 'paypal' in domain,
            'secure' in domain and 'bank' in domain
        ]
        
        return any(indicator for indicator in phishing_indicators)
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious"""
        # Check against known malicious domains
        known_malicious = {
            'bit.ly', 'goo.gl', 'tinyurl.com', 'gooogle.com',
            'faceb00k.com', 'amaz0n.com', 'paypa1.com'
        }
        
        if domain in known_malicious:
            return True
        
        # Check for homograph attacks
        homograph_chars = ['а', 'е', 'і', 'о', 'с', 'ѕ', 'п', 'г']
        if any(char in domain for char in homograph_chars):
            return True
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
        if any(tld in domain for tld in suspicious_tlds):
            return True
        
        return False
    
    def check_redirect_safety(self, url: str) -> Dict[str, Any]:
        """
        Quick check for redirect safety (lightweight version)
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with safety assessment
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Quick checks without following redirects
            indicators = []
            score = 0.0
            
            # Check for URL shorteners
            if any(shortener in domain for shortener in self.url_shorteners):
                indicators.append("URL shortener detected")
                score += 0.5
            
            # Check for suspicious patterns
            suspicious_patterns = [
                'redirect=', 'url=', 'next=', 'goto=', 'destination=',
                'javascript:', 'data:text/html;base64'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in url.lower():
                    indicators.append(f"Suspicious pattern: {pattern}")
                    score += 0.4
            
            # Check for mixed HTTP/HTTPS
            if url.startswith('https://') and 'http://' in url:
                indicators.append("Mixed HTTP/HTTPS protocol")
                score += 0.6
            
            risk_level = "safe"
            if score >= 0.8:
                risk_level = "high"
            elif score >= 0.5:
                risk_level = "medium"
            elif score >= 0.2:
                risk_level = "low"
            
            return {
                "risk_level": risk_level,
                "risk_score": min(score, 1.0),
                "indicators": indicators,
                "safe_to_visit": risk_level == "safe"
            }
            
        except Exception as e:
            logger.error(f"Quick redirect check failed: {str(e)}")
            return {
                "risk_level": "unknown",
                "risk_score": 0.5,
                "indicators": ["Error: " + str(e)],
                "safe_to_visit": False
            }


# Singleton instance
_redirect_checker_instance = None

def get_redirect_checker() -> RedirectHeuristicChecker:
    """Get or create singleton instance"""
    global _redirect_checker_instance
    if _redirect_checker_instance is None:
        _redirect_checker_instance = RedirectHeuristicChecker()
    return _redirect_checker_instance