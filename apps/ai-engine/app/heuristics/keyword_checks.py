# AYUSH WORK AREA
# Keyword-based scam detection heuristics
# Implements CONTEXT.md requirement: Fast non-ML scam keyword detection
# Focuses on banking scams, investment fraud, and urgent action tactics

import re
import logging
from typing import Dict, List, Tuple, Optional
import json
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("keyword_checks")

class KeywordHeuristicChecker:
    """
    Keyword-based scam detection engine
    
    This class implements fast, rule-based checks for scam keywords
    in URLs, text content, and QR payloads. It's designed to:
    
    1. Detect common scam patterns with high precision
    2. Provide contextual explanations for detected indicators
    3. Work efficiently on mobile device constraints
    
    The keyword database is organized by scam category with severity levels.
    Rules are optimized for minimal false positives while catching major threats.
    """
    
    def __init__(self):
        """Initialize keyword rules database"""
        self._initialize_keyword_database()
        logger.info("Keyword heuristic checker initialized with %d keyword groups", len(self.keyword_groups))
    
    def _initialize_keyword_database(self):
        """Initialize scam keyword database"""
        # Banking scam keywords
        self.banking_keywords = {
            "urgent_requests": [
                "urgent", "immediate", "now", "today", "asap", "immediately",
                "critical", "emergency", "alert", "warning"
            ],
            "banking_terms": [
                "bank", "account", "balance", "statement", "transaction",
                "debit", "credit", "card", "visa", "mastercard", "rupay"
            ],
            "credential_requests": [
                "otp", "pin", "password", "cvv", "cvv2", "security code",
                "verification code", "one time password", "auth code"
            ],
            "action_verbs": [
                "verify", "confirm", "update", "activate", "login", "sign in",
                "register", "link", "connect", "sync"
            ],
            "threat_language": [
                "suspended", "blocked", "frozen", "locked", "disabled",
                "terminated", "deactivated", "fraud", "unauthorized"
            ]
        }
        
        # Investment scam keywords
        self.investment_keywords = {
            "returns": [
                "return", "profit", "earn", "income", "revenue", "gain",
                "yield", "dividend", "interest", "ROI", "return on investment"
            ],
            "guarantees": [
                "guaranteed", "100%", "risk-free", "no risk", "safe",
                "certified", "verified", "approved", "official"
            ],
            "crypto_terms": [
                "bitcoin", "btc", "ethereum", "eth", "crypto", "cryptocurrency",
                "blockchain", "mining", "wallet", "exchange", "trading"
            ],
            "urgency": [
                "limited", "exclusive", "only", "few", "last", "final",
                "today", "now", "hurry", "act now", "don't miss"
            ]
        }
        
        # Prize/lottery scam keywords
        self.prize_keywords = {
            "won": [
                "won", "winner", "selected", "congratulations", "lucky",
                "fortunate", "chosen", "picked", "awarded"
            ],
            "prizes": [
                "prize", "lottery", "jackpot", "reward", "gift", "bonus",
                "cash", "money", "fortune", "wealth"
            ],
            "claim": [
                "claim", "redeem", "collect", "receive", "get", "obtain",
                "withdraw", "transfer", "send"
            ],
            "personal_info": [
                "personal", "details", "information", "contact", "address",
                "phone", "email", "identity", "proof"
            ]
        }
        
        # Verification scam keywords
        self.verification_keywords = {
            "verify": [
                "verify", "verification", "confirm", "validation", "authenticate",
                "authorize", "approve", "check", "review"
            ],
            "account": [
                "account", "profile", "identity", "kyc", "aadhaar", "pan",
                "document", "proof", "certificate"
            ],
            "suspended": [
                "suspended", "deactivated", "locked", "disabled", "blocked",
                "frozen", "restricted", "limited"
            ],
            "action": [
                "click", "link", "button", "here", "below", "this", "that"
            ]
        }
        
        # Urgent action scam keywords
        self.urgent_keywords = {
            "urgency": [
                "urgent", "immediate", "now", "today", "asap", "right now",
                "within", "hours", "minutes", "seconds", "deadline"
            ],
            "threats": [
                "threat", "virus", "hacked", "compromised", "breach",
                "attack", "malware", "spyware", "fraud"
            ],
            "consequences": [
                "lose", "penalty", "fine", "legal", "action", "lawsuit",
                "charge", "fee", "cost", "expense"
            ],
            "time_pressure": [
                "before", "until", "by", "end of", "close of", "expiration"
            ]
        }
        
        # QR-specific keywords
        self.qr_keywords = {
            "qr_actions": [
                "scan", "qr code", "barcode", "code", "read", "decode"
            ],
            "qr_purposes": [
                "payment", "login", "verify", "access", "register", "confirm"
            ]
        }
        
        # Combine all keyword groups
        self.keyword_groups = {
            "banking_scam": self.banking_keywords,
            "investment_scam": self.investment_keywords,
            "prize_scam": self.prize_keywords,
            "verification_scam": self.verification_keywords,
            "urgent_action": self.urgent_keywords,
            "qr_phishing": self.qr_keywords
        }
        
        # Severity mapping for keywords
        self.severity_map = {
            "urgent_requests": "high",
            "credential_requests": "high",
            "threat_language": "high",
            "guarantees": "high",
            "crypto_terms": "high",
            "won": "high",
            "personal_info": "high",
            "suspended": "high",
            "threats": "high",
            "consequences": "high",
            "qr_actions": "medium"
        }
    
    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Analyze text for scam keywords
        
        Args:
            text: Text to analyze (URL, QR payload, OCR output)
            
        Returns:
            Dictionary containing:
                - indicators: List of detected scam indicators
                - category_scores: Dictionary of category to score mapping
                - primary_category: Highest scoring category
                - confidence: Overall confidence in detection
                - risk_score: Calculated risk score (0.0-1.0)
        """
        if not text or len(text.strip()) < 5:
            return {
                "indicators": [],
                "category_scores": {},
                "primary_category": "safe",
                "confidence": 0.0,
                "risk_score": 0.0,
                "details": {"text_length": len(text)}
            }
        
        text_lower = text.lower()
        indicators = []
        category_scores = {}
        total_matches = 0
        
        # Check each keyword group
        for category, keyword_group in self.keyword_groups.items():
            category_score = 0.0
            
            # Check each keyword subgroup
            for subgroup, keywords in keyword_group.items():
                matches = []
                for keyword in keywords:
                    # Use word boundaries for exact matches
                    pattern = r'\b' + re.escape(keyword) + r'\b'
                    found = re.findall(pattern, text_lower)
                    if found:
                        matches.extend(found)
                
                if matches:
                    # Calculate subgroup score
                    subgroup_score = len(matches) * 0.1
                    category_score += subgroup_score
                    
                    # Add to indicators
                    severity = self.severity_map.get(subgroup, "medium")
                    indicators.append({
                        "category": category,
                        "subgroup": subgroup,
                        "keyword": matches[0],
                        "count": len(matches),
                        "severity": severity,
                        "score": subgroup_score
                    })
                    
                    total_matches += len(matches)
            
            category_scores[category] = category_score
        
        # Determine primary category
        primary_category = "safe"
        max_score = 0.0
        for category, score in category_scores.items():
            if score > max_score:
                max_score = score
                primary_category = category
        
        # Calculate confidence (based on match count and score)
        confidence = min(total_matches * 0.1, 0.9)
        
        # Calculate risk score (0.0-1.0)
        risk_score = min(max_score * 1.5, 1.0)  # Scale up for impact
        
        return {
            "indicators": indicators,
            "category_scores": category_scores,
            "primary_category": primary_category,
            "confidence": confidence,
            "risk_score": risk_score,
            "details": {
                "text_preview": text[:100] + "..." if len(text) > 100 else text,
                "total_matches": total_matches,
                "analysis_time": datetime.utcnow().isoformat()
            }
        }
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL for scam keywords
        
        Args:
            url: URL to analyze
            
        Returns:
            Same structure as analyze_text but focused on URL components
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        # Analyze different URL components
        components = {
            "full_url": url,
            "domain": parsed.netloc.lower(),
            "path": parsed.path.lower(),
            "query": parsed.query.lower(),
            "fragment": parsed.fragment.lower()
        }
        
        all_indicators = []
        total_score = 0.0
        category_scores = {}
        
        # Analyze each component
        for component_name, component_text in components.items():
            if not component_text:
                continue
                
            result = self.analyze_text(component_text)
            
            # Add component prefix to indicators
            for indicator in result["indicators"]:
                indicator["component"] = component_name
            
            all_indicators.extend(result["indicators"])
            
            # Aggregate scores
            for category, score in result["category_scores"].items():
                category_scores[category] = category_scores.get(category, 0.0) + score
            
            total_score += result["risk_score"]
        
        # Calculate overall metrics
        confidence = min(len(all_indicators) * 0.15, 0.9)
        risk_score = min(total_score * 0.6, 1.0)  # Weight URL components less than full text
        
        return {
            "indicators": all_indicators,
            "category_scores": category_scores,
            "primary_category": self._get_primary_category(category_scores),
            "confidence": confidence,
            "risk_score": risk_score,
            "details": {
                "url": url,
                "components_analyzed": list(components.keys()),
                "indicator_count": len(all_indicators)
            }
        }
    
    def _get_primary_category(self, category_scores: Dict[str, float]) -> str:
        """Get primary category from scores"""
        if not category_scores:
            return "safe"
        
        return max(category_scores.items(), key=lambda x: x[1])[0]
    
    def get_scam_categories(self) -> List[str]:
        """Get all supported scam categories"""
        return list(self.keyword_groups.keys())
    
    def get_keyword_stats(self) -> Dict[str, int]:
        """Get statistics about keyword database"""
        total_keywords = 0
        for group in self.keyword_groups.values():
            for subgroup in group.values():
                total_keywords += len(subgroup)
        
        return {
            "total_categories": len(self.keyword_groups),
            "total_keyword_groups": sum(len(group) for group in self.keyword_groups.values()),
            "total_keywords": total_keywords
        }


# Singleton instance
_keyword_checker_instance = None

def get_keyword_checker() -> KeywordHeuristicChecker:
    """Get or create singleton instance"""
    global _keyword_checker_instance
    if _keyword_checker_instance is None:
        _keyword_checker_instance = KeywordHeuristicChecker()
    return _keyword_checker_instance