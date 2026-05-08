# AYUSH WORK AREA
# Domain-based heuristic checks for phishing detection
# Implements CONTEXT.md requirement: Fast non-ML domain analysis
# Focuses on homograph attacks, suspicious TLDs, and domain anomalies

import re
import logging
from typing import Dict, List, Tuple, Optional
import unicodedata
from urllib.parse import urlparse
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("domain_checks")

class DomainHeuristicChecker:
    """
    Domain-based heuristic analyzer for phishing detection
    
    This class implements fast, rule-based checks for domain anomalies
    without requiring ML model inference. It's designed to be:
    
    1. Extremely fast (microsecond-level per check)
    2. Highly accurate for common phishing patterns
    3. Resilient against evasion techniques
    
    Security Note: These heuristics should be updated regularly as
    scammers evolve their tactics. The rules are based on global threat
    intelligence feeds and real-world phishing samples.
    """
    
    def __init__(self):
        """Initialize domain heuristic rules"""
        self._initialize_rules()
        logger.info("Domain heuristic checker initialized with %d rules", len(self.rules))
    
    def _initialize_rules(self):
        """Initialize domain checking rules"""
        # Suspicious TLDs commonly used in phishing
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
            '.date', '.stream', '.download', '.bid', '.loan', '.review',
            '.online', '.site', '.club', '.info', '.biz'
        }
        
        # Known malicious domains (short list for performance)
        self.known_malicious_domains = {
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co',
            'gooogle.com', 'faceb00k.com', 'amaz0n.com', 'paypa1.com',
            'instagr4m.com', 'tw1tter.com', 'netf1ix.com', 'ub3r.com'
        }
        
        # Common homograph characters (Unicode lookalikes)
        self.homograph_map = {
            'a': ['а', 'ɑ', 'ἀ', 'ἁ', 'ἂ', 'ἃ', 'ἄ', 'ἅ', 'ἆ', 'ἇ'],
            'e': ['е', 'є', 'ҽ', 'ҽ', 'ҿ'],
            'i': ['і', 'ι', 'ί', 'ì', 'í', 'î', 'ï'],
            'o': ['о', 'օ', 'ò', 'ó', 'ô', 'õ', 'ö'],
            'c': ['с', 'ϲ', 'ↄ'],
            's': ['ѕ', 'ʂ', 'ş', 'ŝ'],
            'n': ['п', 'ղ'],
            'r': ['г', 'ŕ', 'ŗ'],
            'u': ['υ', 'ù', 'ú', 'û', 'ü'],
            'v': ['ν', 'ѵ'],
        }
        
        # Domain pattern rules
        self.rules = [
            # Rule 1: IP address in domain
            ("ip_address", self._check_ip_in_domain),
            
            # Rule 2: Suspicious TLD
            ("suspicious_tld", self._check_suspicious_tld),
            
            # Rule 3: Known malicious domain
            ("known_malicious", self._check_known_malicious),
            
            # Rule 4: Homograph attack
            ("homograph_attack", self._check_homograph),
            
            # Rule 5: Long domain name
            ("long_domain", self._check_long_domain),
            
            # Rule 6: Double TLD (e.g., .com.net)
            ("double_tld", self._check_double_tld),
            
            # Rule 7: Short domain (often used for URL shorteners)
            ("short_domain", self._check_short_domain),
            
            # Rule 8: Digits in domain (except for legitimate cases)
            ("digits_in_domain", self._check_digits_in_domain),
            
            # Rule 9: Hyphens in domain (excessive)
            ("excessive_hyphens", self._check_excessive_hyphens),
            
            # Rule 10: Subdomain mimicking path
            ("subdomain_path_mimic", self._check_subdomain_path_mimic),
        ]
    
    def analyze_domain(self, url: str) -> Dict[str, Any]:
        """
        Analyze a URL for domain-based phishing indicators
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing:
                - indicators: List of detected indicators
                - confidence: Overall confidence in detection
                - risk_score: Calculated risk score (0.0-1.0)
                - details: Additional technical details
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            if not domain:
                return {
                    "indicators": [],
                    "confidence": 0.0,
                    "risk_score": 0.0,
                    "details": {"error": "Invalid URL format"}
                }
            
            indicators = []
            total_score = 0.0
            
            # Run all domain checks
            for rule_name, rule_func in self.rules:
                try:
                    result = rule_func(domain, url)
                    if result["detected"]:
                        indicators.append({
                            "rule": rule_name,
                            "description": result["description"],
                            "severity": result["severity"],
                            "score": result["score"]
                        })
                        total_score += result["score"]
                except Exception as e:
                    logger.warning(f"Rule {rule_name} failed for {url}: {str(e)}")
            
            # Calculate confidence (higher with more indicators)
            confidence = min(len(indicators) * 0.2, 0.9)
            
            # Normalize risk score (max 1.0)
            risk_score = min(total_score, 1.0)
            
            return {
                "indicators": indicators,
                "confidence": confidence,
                "risk_score": risk_score,
                "details": {
                    "domain": domain,
                    "url": url,
                    "indicator_count": len(indicators),
                    "analysis_time": datetime.utcnow().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Domain analysis failed for {url}: {str(e)}", exc_info=True)
            return {
                "indicators": [],
                "confidence": 0.0,
                "risk_score": 0.5,
                "details": {"error": str(e)}
            }
    
    def _check_ip_in_domain(self, domain: str, url: str) -> Dict[str, Any]:
        """Check if domain contains IP address"""
        # Simple IP regex
        ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$'
        if re.match(ip_pattern, domain):
            return {
                "detected": True,
                "description": "Domain is an IP address (common in phishing)",
                "severity": "high",
                "score": 0.8
            }
        
        # Check for IP in subdomain
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            return {
                "detected": True,
                "description": "IP address found in domain/subdomain",
                "severity": "high",
                "score": 0.7
            }
        
        return {"detected": False}
    
    def _check_suspicious_tld(self, domain: str, url: str) -> Dict[str, Any]:
        """Check for suspicious TLDs"""
        # Extract TLD
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = f".{parts[-1]}"
            if tld in self.suspicious_tlds:
                return {
                    "detected": True,
                    "description": f"Suspicious TLD: {tld}",
                    "severity": "medium",
                    "score": 0.6
                }
        
        return {"detected": False}
    
    def _check_known_malicious(self, domain: str, url: str) -> Dict[str, Any]:
        """Check against known malicious domains"""
        # Check full domain
        if domain in self.known_malicious_domains:
            return {
                "detected": True,
                "description": f"Known malicious domain: {domain}",
                "severity": "high",
                "score": 0.9
            }
        
        # Check base domain (without www, etc.)
        base_domain = domain.replace('www.', '').replace('m.', '')
        if base_domain in self.known_malicious_domains:
            return {
                "detected": True,
                "description": f"Known malicious base domain: {base_domain}",
                "severity": "high",
                "score": 0.8
            }
        
        return {"detected": False}
    
    def _check_homograph(self, domain: str, url: str) -> Dict[str, Any]:
        """Check for homograph attacks (Unicode lookalike characters)"""
        # Normalize domain to NFC form
        normalized = unicodedata.normalize('NFC', domain)
        
        # Check each character against homograph map
        suspicious_chars = []
        for char in normalized:
            for original, lookalikes in self.homograph_map.items():
                if char in lookalikes:
                    suspicious_chars.append(f"{char}({original})")
        
        if suspicious_chars:
            return {
                "detected": True,
                "description": f"Homograph attack detected: {', '.join(suspicious_chars[:3])}",
                "severity": "high",
                "score": 0.85
            }
        
        return {"detected": False}
    
    def _check_long_domain(self, domain: str, url: str) -> Dict[str, Any]:
        """Check for excessively long domains"""
        if len(domain) > 45:
            return {
                "detected": True,
                "description": f"Excessively long domain ({len(domain)} chars)",
                "severity": "medium",
                "score": 0.5
            }
        
        return {"detected": False}
    
    def _check_double_tld(self, domain: str, url: str) -> Dict[str, Any]:
        """Check for double TLD (e.g., example.com.net)"""
        parts = domain.split('.')
        if len(parts) >= 3:
            # Check if last two parts form a suspicious combination
            tld1 = parts[-1]
            tld2 = parts[-2]
            if tld1 in ['com', 'net', 'org'] and tld2 in ['co', 'io', 'ai', 'app']:
                return {
                    "detected": True,
                    "description": f"Double TLD pattern: {tld2}.{tld1}",
                    "severity": "medium",
                    "score": 0.6
                }
            elif len(tld1) <= 3 and len(tld2) <= 3:
                # Short TLD followed by another short TLD
                return {
                    "detected": True,
                    "description": "Suspicious double TLD pattern",
                    "severity": "medium",
                    "score": 0.5
                }
        
        return {"detected": False}
    
    def _check_short_domain(self, domain: str, url: str) -> Dict[str, Any]:
        """Check for very short domains (URL shorteners)"""
        if len(domain) <= 8 and not domain.endswith('.com'):
            return {
                "detected": True,
                "description": f"Very short domain ({len(domain)} chars)",
                "severity": "medium",
                "score": 0.4
            }
        
        return {"detected": False}
    
    def _check_digits_in_domain(self, domain: str, url: str) -> Dict[str, Any]:
        """Check for excessive digits in domain"""
        digit_count = sum(1 for c in domain if c.isdigit())
        total_chars = len(domain)
        
        if digit_count > 0 and digit_count / total_chars > 0.4:
            return {
                "detected": True,
                "description": f"Excessive digits in domain ({digit_count}/{total_chars})",
                "severity": "medium",
                "score": 0.5
            }
        
        return {"detected": False}
    
    def _check_excessive_hyphens(self, domain: str, url: str) -> Dict[str, Any]:
        """Check for excessive hyphens in domain"""
        hyphen_count = domain.count('-')
        if hyphen_count > 3:
            return {
                "detected": True,
                "description": f"Excessive hyphens ({hyphen_count}) in domain",
                "severity": "medium",
                "score": 0.4
            }
        
        return {"detected": False}
    
    def _check_subdomain_path_mimic(self, domain: str, url: str) -> Dict[str, Any]:
        """Check if subdomain mimics a path (e.g., login.google.com vs google.com/login)"""
        parsed = urlparse(url)
        path = parsed.path
        
        # Check if subdomain contains common path words
        subdomains = domain.split('.')[:-2]  # Exclude TLD and domain
        path_words = ['login', 'signin', 'account', 'verify', 'secure', 'payment']
        
        for subdomain in subdomains:
            for word in path_words:
                if word in subdomain.lower():
                    return {
                        "detected": True,
                        "description": f"Subdomain mimics path: {subdomain} (like '{word}')",
                        "severity": "high",
                        "score": 0.7
                    }
        
        return {"detected": False}


# Singleton instance
_domain_checker_instance = None

def get_domain_checker() -> DomainHeuristicChecker:
    """Get or create singleton instance"""
    global _domain_checker_instance
    if _domain_checker_instance is None:
        _domain_checker_instance = DomainHeuristicChecker()
    return _domain_checker_instance