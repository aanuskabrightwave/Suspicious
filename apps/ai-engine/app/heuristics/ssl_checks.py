# AYUSH WORK AREA
# SSL/TLS certificate heuristic checks
# Implements CONTEXT.md requirement: Certificate validation heuristics
# Focuses on expired certificates, mismatched domains, and weak cipher suites

import ssl
import socket
import logging
from typing import Dict, List, Tuple, Optional, Union
from datetime import datetime, timezone
import OpenSSL
from urllib.parse import urlparse
import requests

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("ssl_checks")

class SSLHeuristicChecker:
    """
    SSL/TLS certificate analysis heuristics
    
    This class implements fast, rule-based checks for SSL certificate issues
    without requiring full certificate validation. It's designed to:
    
    1. Detect common certificate problems that indicate phishing
    2. Work efficiently even when full certificate validation is not possible
    3. Provide contextual explanations for detected issues
    
    Security Note: SSL checks should complement, not replace, proper
    certificate validation. This heuristic approach catches obvious issues
    quickly before more expensive validation.
    """
    
    def __init__(self):
        """Initialize SSL checking rules"""
        self._initialize_rules()
        logger.info("SSL heuristic checker initialized")
    
    def _initialize_rules(self):
        """Initialize SSL checking rules"""
        # Weak cipher suites (common in phishing sites)
        self.weak_ciphers = {
            'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'SHA1',
            'TLS_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        }
        
        # Suspicious certificate issuers
        self.suspicious_issuers = {
            'Let\'s Encrypt',  # Not inherently suspicious, but often used in phishing
            'Cloudflare Inc',  # Often used in proxy-based phishing
            'ZeroSSL',  # Free certs, sometimes abused
            'RapidSSL',  # Sometimes used in phishing
            'GeoTrust',  # Legacy, sometimes abused
        }
        
        # Common phishing certificate patterns
        self.phishing_patterns = [
            # Pattern 1: Certificate subject doesn't match domain
            ("subject_domain_mismatch", self._check_subject_domain_mismatch),
            
            # Pattern 2: Expired certificate
            ("expired_certificate", self._check_expired_certificate),
            
            # Pattern 3: Self-signed certificate
            ("self_signed", self._check_self_signed),
            
            # Pattern 4: Wildcard certificate for suspicious domains
            ("wildcard_suspicious", self._check_wildcard_suspicious),
            
            # Pattern 5: Certificate issued recently (newly created phishing sites)
            ("recently_issued", self._check_recently_issued),
        ]
    
    def analyze_ssl(self, url: str) -> Dict[str, Any]:
        """
        Analyze SSL/TLS certificate for a URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary containing:
                - indicators: List of detected SSL issues
                - risk_score: Calculated risk score (0.0-1.0)
                - confidence: Confidence in detection
                - details: Additional technical details
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if not domain:
                return {
                    "indicators": [],
                    "risk_score": 0.0,
                    "confidence": 0.0,
                    "details": {"error": "Invalid URL format"}
                }
            
            # Get SSL certificate info
            cert_info = self._get_certificate_info(domain)
            
            if not cert_info:
                return {
                    "indicators": [{"rule": "no_certificate", "description": "No SSL certificate available", "severity": "high", "score": 0.9}],
                    "risk_score": 0.9,
                    "confidence": 0.8,
                    "details": {"domain": domain}
                }
            
            indicators = []
            total_score = 0.0
            
            # Run SSL checks
            for rule_name, rule_func in self.phishing_patterns:
                try:
                    result = rule_func(cert_info, domain)
                    if result["detected"]:
                        indicators.append({
                            "rule": rule_name,
                            "description": result["description"],
                            "severity": result["severity"],
                            "score": result["score"]
                        })
                        total_score += result["score"]
                except Exception as e:
                    logger.warning(f"SSL rule {rule_name} failed for {domain}: {str(e)}")
            
            # Check for weak cipher suites (if available)
            if cert_info.get("cipher_suite"):
                cipher = cert_info["cipher_suite"].upper()
                if any(weak in cipher for weak in self.weak_ciphers):
                    indicators.append({
                        "rule": "weak_cipher",
                        "description": f"Weak cipher suite: {cipher}",
                        "severity": "high",
                        "score": 0.7
                    })
                    total_score += 0.7
            
            # Check issuer
            issuer = cert_info.get("issuer", "")
            if any(suspicious in issuer for suspicious in self.suspicious_issuers):
                indicators.append({
                    "rule": "suspicious_issuer",
                    "description": f"Suspicious certificate issuer: {issuer}",
                    "severity": "medium",
                    "score": 0.5
                })
                total_score += 0.5
            
            # Calculate confidence
            confidence = min(len(indicators) * 0.2, 0.9)
            
            # Normalize risk score
            risk_score = min(total_score, 1.0)
            
            return {
                "indicators": indicators,
                "risk_score": risk_score,
                "confidence": confidence,
                "details": {
                    "domain": domain,
                    "certificate_issuer": cert_info.get("issuer", "Unknown"),
                    "valid_from": cert_info.get("valid_from"),
                    "valid_until": cert_info.get("valid_until"),
                    "subject": cert_info.get("subject", {}),
                    "analysis_time": datetime.utcnow().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"SSL analysis failed for {url}: {str(e)}", exc_info=True)
            return {
                "indicators": [],
                "risk_score": 0.5,
                "confidence": 0.0,
                "details": {"error": str(e)}
            }
    
    def _get_certificate_info(self, domain: str) -> Dict[str, Any]:
        """
        Get SSL certificate information for a domain
        
        Args:
            domain: Domain to check
            
        Returns:
            Dictionary with certificate information
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect to server
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Get certificate
                    cert = ssock.getpeercert()
                    
                    # Get cipher suite
                    cipher = ssock.cipher()
                    
                    # Parse certificate info
                    info = {
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "cipher_suite": cipher[0] if cipher else None
                    }
                    
                    # Convert dates to ISO format
                    if info["not_before"]:
                        info["valid_from"] = datetime.strptime(info["not_before"], "%b %d %H:%M:%S %Y %Z").isoformat()
                    if info["not_after"]:
                        info["valid_until"] = datetime.strptime(info["not_after"], "%b %d %H:%M:%S %Y %Z").isoformat()
                    
                    return info
                    
        except Exception as e:
            logger.warning(f"Failed to get certificate for {domain}: {str(e)}")
            return {}
    
    def _check_subject_domain_mismatch(self, cert_info: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Check if certificate subject doesn't match domain"""
        subject = cert_info.get("subject", {})
        cn = subject.get("commonName", "")
        
        # Check for exact match
        if cn.lower() == domain.lower():
            return {"detected": False}
        
        # Check for wildcard match
        if cn.startswith('*.') and domain.endswith(cn[2:]):
            return {"detected": False}
        
        # Check for partial match (common in phishing)
        if cn.lower() in domain.lower() or domain.lower() in cn.lower():
            return {
                "detected": True,
                "description": f"Certificate subject '{cn}' doesn't match domain '{domain}'",
                "severity": "high",
                "score": 0.8
            }
        
        return {"detected": False}
    
    def _check_expired_certificate(self, cert_info: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Check if certificate is expired"""
        valid_until = cert_info.get("valid_until")
        if not valid_until:
            return {"detected": False}
        
        try:
            expiry_date = datetime.fromisoformat(valid_until).replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            
            if expiry_date < now:
                return {
                    "detected": True,
                    "description": f"Certificate expired on {valid_until}",
                    "severity": "high",
                    "score": 0.9
                }
        except Exception as e:
            logger.warning(f"Date parsing failed: {str(e)}")
        
        return {"detected": False}
    
    def _check_self_signed(self, cert_info: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Check if certificate is self-signed"""
        issuer = cert_info.get.get