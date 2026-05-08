# AYUSH WORK AREA
# URL scanner module for phishing detection
# Implements CONTEXT.md: "URL Phishing Scan Flow: Extract -> Analyze -> Score -> Classify"
# Focuses on comprehensive URL analysis combining heuristic checks and ML classification

import logging
import re
import time
from typing import Dict, List, Tuple, Optional, Any
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime
import hashlib

# Local imports
from app.utils.logger import setup_logger
from app.config import settings
from app.heuristics.domain_checks import get_domain_checker
from app.heuristics.keyword_checks import get_keyword_checker
from app.heuristics.redirect_checks import get_redirect_checker
from app.classifiers.phishing_classifier import get_phishing_classifier
from app.classifiers.risk_classifier import get_risk_classifier

logger = setup_logger("url_scanner")

class URLScanner:
    """
    Comprehensive URL phishing scanner
    
    This class implements the complete URL analysis pipeline:
    1. URL structure analysis (domain, path, query parameters)
    2. Heuristic checks (domain homographs, suspicious patterns, keywords)
    3. ML-based classification (if confidence threshold not met by heuristics)
    4. Risk scoring and explanation generation
    
    The scanner is optimized for speed with caching and early exit conditions
    for high-confidence heuristic detections.
    """
    
    def __init__(self):
        """Initialize URL scanning components"""
        self.domain_checker = get_domain_checker()
        self.keyword_checker = get_keyword_checker()
        self.redirect_checker = get_redirect_checker()
        self.phishing_classifier = get_phishing_classifier()
        self.risk_classifier = get_risk_classifier()
        
        # Initialize URL-specific patterns
        self._initialize_patterns()
        logger.info("URLScanner initialized")
    
    def _initialize_patterns(self):
        """Initialize URL analysis patterns and rules"""
        # Suspicious URL patterns
        self.suspicious_patterns = {
            'query_params': [
                'redirect', 'url', 'next', 'return', 'goto', 'destination',
                'continue', 'callback', 'back', 'view', 'target'
            ],
            'path_patterns': [
                r'/login', r'/signin', r'/account', r'/verify', r'/secure',
                r'/payment', r'/checkout', r'/confirm', r'/update', r'/admin'
            ],
            'subdomain_patterns': [
                'login', 'signin', 'account', 'verify', 'secure', 'payment'
            ]
        }
        
        # Common legitimate domains (to detect impersonation)
        self.legitimate_domains = {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'paypal.com', 'netflix.com', 'instagram.com',
            'twitter.com', 'linkedin.com', 'youtube.com', 'github.com',
            'whatsapp.com', 'telegram.org', 'snapchat.com', 'tiktok.com'
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
            '.date', '.stream', '.download', '.bid', '.loan', '.review'
        }
    
    def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Scan URL for phishing indicators
        
        Args:
            url: URL to scan
            
        Returns:
            Dictionary with scan results including:
                - risk_score: Overall risk score (0.0-1.0)
                - category: Detected threat category
                - explanation: User-friendly explanation
                - details: Technical details
        """
        start_time = time.time()
        
        try:
            # Validate URL format
            if not self._is_valid_url(url):
                return {
                    "risk_score": 1.0,
                    "category": "invalid_url",
                    "explanation": "Invalid URL format. Please enter a valid HTTP/HTTPS URL.",
                    "details": {
                        "analysis_time_ms": round((time.time() - start_time) * 1000, 2),
                        "error": "Invalid URL format"
                    }
                }
            
            # Sanitize URL
            sanitized_url = self._sanitize_url(url)
            
            # Perform comprehensive analysis
            url_analysis = self._analyze_url_structure(sanitized_url)
            domain_analysis = self.domain_checker.analyze_domain(sanitized_url)
            keyword_analysis = self.keyword_checker.analyze_url(sanitized_url)
            
            # Calculate initial risk score from heuristics
            heuristic_risk = self._calculate_heuristic_risk(
                url_analysis, domain_analysis, keyword_analysis
            )
            
            # If heuristic confidence is high enough, skip ML classification
            if heuristic_risk >= settings.HEURISTIC_CONFIDENCE_THRESHOLD:
                # Use heuristic results directly
                risk_score = heuristic_risk
                category = self._determine_category_from_heuristics(
                    domain_analysis, keyword_analysis
                )
                explanation = self._generate_explanation(
                    risk_score, category, url_analysis, domain_analysis, keyword_analysis
                )
            else:
                # Use ML classification for additional analysis
                phishing_score, phishing_confidence, phishing_meta = self.phishing_classifier.predict(sanitized_url)
                
                # Combine heuristic and ML scores
                risk_score = self._combine_scores(heuristic_risk, phishing_score, phishing_confidence)
                category = self._determine_category_from_ml(phishing_score, keyword_analysis)
                explanation = self._generate_explanation(
                    risk_score, category, url_analysis, domain_analysis, keyword_analysis
                )
            
            # Final risk assessment using unified classifier
            risk_result = self.risk_classifier.assess_url_risk(sanitized_url)
            final_risk_score = risk_result['risk_score']
            
            return {
                "risk_score": final_risk_score,
                "category": risk_result['risk_level'],
                "explanation": risk_result['explanation'],
                "details": {
                    "url_analysis": url_analysis,
                    "domain_analysis": domain_analysis,
                    "keyword_analysis": keyword_analysis,
                    "phishing_classification": {
                        "score": phishing_score,
                        "confidence": phishing_confidence,
                        "metadata": phishing_meta
                    },
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2),
                    "url_hash": hashlib.sha256(sanitized_url.encode()).hexdigest()[:16],
                    "original_url": url,
                    "sanitized_url": sanitized_url
                }
            }
            
        except Exception as e:
            logger.error(f"URL scanning failed: {str(e)}", exc_info=True)
            return {
                "risk_score": 0.5,
                "category": "error",
                "explanation": "Failed to analyze URL. Please try again.",
                "details": {
                    "error": str(e),
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            }
    
    def _is_valid_url(self, url: str) -> bool:
        """
        Validate URL format
        
        Args:
            url: URL string to validate
            
        Returns:
            True if URL is valid
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _sanitize_url(self, url: str) -> str:
        """
        Sanitize URL by removing common obfuscation techniques
        
        Args:
            url: URL to sanitize
            
        Returns:
            Sanitized URL string
        """
        # Remove leading/trailing whitespace
        url = url.strip()
        
        # Decode percent-encoded characters
        try:
            url = unquote(url)
        except Exception:
            pass
        
        # Remove common obfuscation patterns
        # Remove extra slashes
        url = re.sub(r'/{2,}', '/', url)
        
        # Remove trailing dots from domain
        parsed = urlparse(url)
        if parsed.netloc.endswith('.'):
            netloc = parsed.netloc.rstrip('.')
            url = f"{parsed.scheme}://{netloc}{parsed.path}{parsed.query}{parsed.fragment}"
        
        return url
    
    def _analyze_url_structure(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL structure for suspicious patterns
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with structural analysis results
        """
        try:
            parsed = urlparse(url)
            
            # Analyze components
            scheme = parsed.scheme.lower()
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            fragment = parsed.fragment.lower()
            
            # Check for suspicious patterns
            suspicious_elements = []
            
            # Check for suspicious query parameters
            query_params = parse_qs(parsed.query)
            for param in self.suspicious_patterns['query_params']:
                if param in query_params:
                    suspicious_elements.append(f"query_param:{param}")
            
            # Check for suspicious path patterns
            for pattern in self.suspicious_patterns['path_patterns']:
                if re.search(pattern, path):
                    suspicious_elements.append(f"path_pattern:{pattern}")
            
            # Check for suspicious subdomain patterns
            domain_parts = domain.split('.')
            for part in domain_parts[:-2]:  # Exclude TLD and domain
                if part in self.suspicious_patterns['subdomain_patterns']:
                    suspicious_elements.append(f"subdomain:{part}")
            
            # Check for IP address in domain
            is_ip_address = bool(re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
            
            # Check for excessive length
            url_length = len(url)
            is_long_url = url_length > 100
            
            # Check for multiple domains (redirects)
            contains_multiple_domains = len(re.findall(r'https?://[^/]+', url)) > 1
            
            # Check for encoded characters
            encoded_chars = len(re.findall(r'%[0-9A-Fa-f]{2}', url))
            
            return {
                "scheme": scheme,
                "domain": domain,
                "path": path,
                "query": query,
                "fragment": fragment,
                "url_length": url_length,
                "query_params_count": len(query_params),
                "path_segments_count": len(path.split('/')),
                "suspicious_elements": suspicious_elements,
                "is_ip_address": is_ip_address,
                "is_long_url": is_long_url,
                "contains_multiple_domains": contains_multiple_domains,
                "encoded_chars_count": encoded_chars,
                "has_credentials": '@' in parsed.netloc
            }
            
        except Exception as e:
            logger.error(f"URL structure analysis failed: {str(e)}")
            return {"error": str(e)}
    
    def _calculate_heuristic_risk(
        self, 
        url_analysis: Dict[str, Any], 
        domain_analysis: Dict[str, Any], 
        keyword_analysis: Dict[str, Any]
    ) -> float:
        """
        Calculate risk score from heuristic analysis
        
        Args:
            url_analysis: URL structure analysis
            domain_analysis: Domain analysis results
            keyword_analysis: Keyword analysis results
            
        Returns:
            Heuristic risk score (0.0-1.0)
        """
        score = 0.0
        
        # Domain-based risk
        domain_risk = domain_analysis.get("risk_score", 0.0)
        score += domain_risk * 0.4
        
        # Keyword-based risk
        keyword_risk = keyword_analysis.get("risk_score", 0.0)
        score += keyword_risk * 0.3
        
        # URL structure risk
        if url_analysis.get("is_ip_address"):
            score += 0.3
        
        if url_analysis.get("is_long_url"):
            score += 0.2
        
        if url_analysis.get("has_credentials"):
            score += 0.4
        
        suspicious_count = len(url_analysis.get("suspicious_elements", []))
        score += suspicious_count * 0.1
        
        # Limit to 1.0
        return min(score, 1.0)
    
    def _determine_category_from_heuristics(
        self, 
        domain_analysis: Dict[str, Any], 
        keyword_analysis: Dict[str, Any]
    ) -> str:
        """
        Determine threat category from heuristic analysis
        
        Args:
            domain_analysis: Domain analysis results
            keyword_analysis: Keyword analysis results
            
        Returns:
            Threat category string
        """
        # Check for phishing indicators
        domain_indicators = domain_analysis.get("indicators", [])
        keyword_indicators = keyword_analysis.get("indicators", [])
        
        all_indicators = domain_indicators + keyword_indicators
        
        # Check for banking-related indicators
        banking_indicators = [
            "credential_request", "banking_scam", "otp", "pin", "password"
        ]
        
        if any(indicator in str(all_indicators).lower() for indicator in banking_indicators):
            return "banking_phishing"
        
        # Check for general phishing
        phishing_indicators = [
            "homograph_attack", "suspicious_tld", "ip_address", "known_malicious"
        ]
        
        if any(indicator in str(all_indicators).lower() for indicator in phishing_indicators):
            return "phishing"
        
        # Check for suspicious activity
        if all_indicators:
            return "suspicious"
        
        return "safe"
    
    def _determine_category_from_ml(
        self, 
        phishing_score: float, 
        keyword_analysis: Dict[str, Any]
    ) -> str:
        """
        Determine threat category from ML classification
        
        Args:
            phishing_score: Phishing classifier score
            keyword_analysis: Keyword analysis results
            
        Returns:
            Threat category string
        """
        if phishing_score >= 0.8:
            return "phishing"
        elif phishing_score >= 0.6:
            return "suspicious"
        elif phishing_score >= 0.4:
            return "caution"
        else:
            return "safe"
    
    def _combine_scores(
        self, 
        heuristic_score: float, 
        ml_score: float, 
        ml_confidence: float
    ) -> float:
        """
        Combine heuristic and ML scores
        
        Args:
            heuristic_score: Heuristic-based risk score
            ml_score: ML classifier risk score
            ml_confidence: ML classifier confidence
            
        Returns:
            Combined risk score
        """
        # Weight heuristic score higher if ML confidence is low
        if ml_confidence < 0.5:
            return heuristic_score * 0.7 + ml_score * 0.3
        
        # Otherwise, use weighted average
        return heuristic_score * 0.4 + ml_score * 0.6
    
    def _generate_explanation(
        self, 
        risk_score: float, 
        category: str, 
        url_analysis: Dict[str, Any], 
        domain_analysis: Dict[str, Any], 
        keyword_analysis: Dict[str, Any]
    ) -> str:
        """
        Generate user-friendly explanation for URL scan results
        
        Args:
            risk_score: Calculated risk score
            category: Threat category
            url_analysis: URL structure analysis
            domain_analysis: Domain analysis
            keyword_analysis: Keyword analysis
            
        Returns:
            Human-readable explanation
        """
        if risk_score < 0.3:
            return "This URL appears safe. No significant phishing indicators detected."
        
        explanations = {
            "phishing": "This URL shows strong indicators of a phishing attempt. Avoid entering any personal information.",
            "banking_phishing": "This URL appears to be a fake banking site attempting to steal your login credentials.",
            "suspicious": "This URL has suspicious characteristics that warrant caution.",
            "caution": "This URL has some concerning elements. Proceed with care.",
            "safe": "This URL appears safe. No significant security concerns detected."
        }
        
        base_explanation = explanations.get(category, "This URL has security concerns that require attention.")
        
        # Add specific indicators
        indicators = []
        
        # Domain indicators
        domain_inds = domain_analysis.get("indicators", [])
        if domain_inds:
            for ind in domain_inds[:2]:
                if isinstance(ind, dict):
                    indicators.append(ind.get("description", ""))
                else:
                    indicators.append(str(ind))
        
        # Keyword indicators
        keyword_inds = keyword_analysis.get("indicators", [])
        if keyword_inds:
            for ind in keyword_inds[:2]:
                if isinstance(ind, dict):
                    indicators.append(ind.get("description", ""))
                else:
                    indicators.append(str(ind))
        
        # URL structure indicators
        suspicious_elements = url_analysis.get("suspicious_elements", [])
        if suspicious_elements:
            indicators.extend(suspicious_elements[:2])
        
        if indicators:
            indicator_str = ", ".join([f'"{ind}"' for ind in indicators if ind])
            if indicator_str:
                return f"{base_explanation} Detected: {indicator_str}."
        
        return base_explanation
    
    def batch_scan_urls(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        Batch scan multiple URLs
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            List of scan results
        """
        results = []
        for url in urls:
            try:
                result = self.scan_url(url)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch scan failed for URL {url}: {str(e)}")
                results.append({
                    "risk_score": 0.5,
                    "category": "error",
                    "explanation": "Failed to analyze URL",
                    "details": {"error": str(e)}
                })
        
        return results


# Singleton instance
_url_scanner_instance = None

def get_url_scanner() -> URLScanner:
    """Get or create singleton instance"""
    global _url_scanner_instance
    if _url_scanner_instance is None:
        _url_scanner_instance = URLScanner()
    return _url_scanner_instance