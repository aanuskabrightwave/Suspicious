# AYUSH WORK AREA
# Scam text detection module for OCR-extracted content
# Implements CONTEXT.md: "Heuristic Engine: Fast non-ML checks for scam keywords"
# Focuses on detecting WhatsApp/SMS scams in extracted text

import re
import logging
from typing import Dict, List, Tuple, Optional
import time
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.heuristics.keyword_checks import get_keyword_checker
from app.heuristics.domain_checks import get_domain_checker
from app.config import settings

logger = setup_logger("scam_text_detector")

class ScamTextDetector:
    """
    Scam detection for OCR-extracted text content
    
    This class implements the second stage of the OCR pipeline:
    1. Analyze extracted text for scam indicators
    2. Detect phishing URLs within the text
    3. Identify manipulation tactics and urgency language
    4. Generate risk assessment and explanation
    
    The detector combines heuristic rules with keyword matching
    to provide fast, accurate scam detection without ML overhead.
    """
    
    def __init__(self):
        """Initialize scam detection components"""
        self.keyword_checker = get_keyword_checker()
        self.domain_checker = get_domain_checker()
        self.scam_categories = [
            "banking_scam", "investment_scam", "prize_scam",
            "verification_scam", "urgent_action", "qr_phishing"
        ]
        logger.info("ScamTextDetector initialized")
    
    def detect_scams_in_text(self, text: str) -> Dict[str, Any]:
        """
        Detect scams in extracted text
        
        Args:
            text: OCR-extracted text to analyze
            
        Returns:
            Dictionary containing:
                - risk_score: Overall risk score (0.0-1.0)
                - category: Primary scam category
                - indicators: List of detected scam indicators
                - explanation: User-friendly explanation
                - details: Technical details for debugging
        """
        start_time = time.time()
        
        try:
            if not text or len(text.strip()) < 5:
                return {
                    "risk_score": 0.0,
                    "category": "safe",
                    "indicators": [],
                    "explanation": "No text to analyze",
                    "details": {
                        "text_length": len(text),
                        "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
                    }
                }
            
            # 1. Keyword-based scam detection
            keyword_result = self.keyword_checker.analyze_text(text)
            
            # 2. URL detection and analysis within text
            urls = self._extract_urls_from_text(text)
            url_results = []
            for url in urls[:3]:  # Limit to first 3 URLs for performance
                try:
                    domain_result = self.domain_checker.analyze_domain(url)
                    url_results.append({
                        "url": url,
                        "domain_analysis": domain_result,
                        "risk_score": domain_result["risk_score"]
                    })
                except Exception as e:
                    logger.warning(f"URL analysis failed for {url}: {str(e)}")
            
            # 3. Calculate overall risk score
            risk_score = self._calculate_overall_risk(
                keyword_result, 
                url_results,
                len(urls)
            )
            
            # 4. Determine primary category
            primary_category = self._determine_primary_category(keyword_result)
            
            # 5. Generate explanation
            explanation = self._generate_explanation(
                risk_score, 
                primary_category, 
                keyword_result["indicators"],
                url_results
            )
            
            # 6. Compile results
            result = {
                "risk_score": risk_score,
                "category": primary_category,
                "indicators": keyword_result["indicators"],
                "explanation": explanation,
                "details": {
                    "text_preview": text[:200] + "..." if len(text) > 200 else text,
                    "url_count": len(urls),
                    "keyword_matches": len(keyword_result["indicators"]),
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2),
                    "url_analyses": url_results
                }
            }
            
            logger.debug(
                f"Scam detection completed: score={risk_score:.4f}, category={primary_category}"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Scam detection failed: {str(e)}", exc_info=True)
            return {
                "risk_score": 0.5,
                "category": "unknown",
                "indicators": [{"rule": "error", "description": str(e), "severity": "high", "score": 0.5}],
                "explanation": "Error occurred during scam detection",
                "details": {
                    "error": str(e),
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            }
    
    def _extract_urls_from_text(self, text: str) -> List[str]:
        """
        Extract URLs from text using regex
        
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
                logger.debug(f"Cleaned URL: {url} -> {clean_url}")
            cleaned_urls.append(clean_url)
        
        return list(set(cleaned_urls))  # Remove duplicates
    
    def _calculate_overall_risk(
        self, 
        keyword_result: Dict[str, Any], 
        url_results: List[Dict[str, Any]],
        url_count: int
    ) -> float:
        """
        Calculate overall risk score from multiple indicators
        
        Args:
            keyword_result: Keyword analysis results
            url_results: URL analysis results
            url_count: Number of URLs found
            
        Returns:
            Risk score 0.0-1.0
        """
        # Base risk from keyword analysis
        base_risk = keyword_result["risk_score"]
        
        # Boost for URLs (especially suspicious ones)
        url_risk_boost = 0.0
        if url_results:
            # Average risk of URLs
            url_risks = [r["domain_analysis"]["risk_score"] for r in url_results]
            avg_url_risk = sum(url_risks) / len(url_risks)
            
            # Weight URL risk (higher weight for more URLs)
            url_risk_boost = avg_url_risk * 0.4 * min(url_count, 3) / 3
        
        # Boost for high-confidence keyword matches
        confidence_boost = keyword_result["confidence"] * 0.3
        
        # Total risk
        total_risk = base_risk + url_risk_boost + confidence_boost
        
        # Apply caps and floors
        risk_score = max(0.0, min(1.0, total_risk))
        
        return risk_score
    
    def _determine_primary_category(self, keyword_result: Dict[str, Any]) -> str:
        """
        Determine primary scam category from keyword analysis
        
        Args:
            keyword_result: Keyword analysis results
            
        Returns:
            Primary category string
        """
        if not keyword_result["indicators"]:
            return "safe"
        
        # Group indicators by category
        category_scores = {}
        for indicator in keyword_result["indicators"]:
            category = indicator.get("category", "unknown")
            score = indicator.get("score", 0.0)
            category_scores[category] = category_scores.get(category, 0.0) + score
        
        # Get highest scoring category
        if category_scores:
            primary_category = max(category_scores.items(), key=lambda x: x[1])[0]
            return primary_category
        
        return "safe"
    
    def _generate_explanation(
        self,
        risk_score: float,
        category: str,
        indicators: List[Dict[str, Any]],
        url_results: List[Dict[str, Any]]
    ) -> str:
        """
        Generate user-friendly explanation for scam detection
        
        Args:
            risk_score: Calculated risk score
            category: Primary scam category
            indicators: Detected scam indicators
            url_results: URL analysis results
            
        Returns:
            Human-readable explanation
        """
        if risk_score < 0.3:
            return "This content appears safe. No significant scam indicators detected."
        
        # Category-specific explanations
        explanations = {
            "banking_scam": "This message contains suspicious banking requests. Legitimate banks never ask for your PIN or OTP via messages.",
            "investment_scam": "This appears to be an investment scam promising unrealistic returns. Be cautious of 'get rich quick' schemes.",
            "prize_scam": "This is likely a fake prize or lottery notification. You cannot win a prize you never entered.",
            "verification_scam": "This appears to be a fake account verification request designed to steal your login credentials.",
            "urgent_action": "This message creates false urgency to trick you into taking immediate action without thinking.",
            "qr_phishing": "This QR code may lead to a malicious website. Verify the source before scanning."
        }
        
        base_explanation = explanations.get(category, "This content contains indicators of a potential scam.")
        
        # Add specific indicators if present
        if indicators:
            indicator_list = []
            for ind in indicators[:3]:  # Limit to top 3 indicators
                desc = ind.get("description", "")
                if desc and desc not in indicator_list:
                    indicator_list.append(desc)
            
            if indicator_list:
                indicator_str = ", ".join([f'"{ind}"' for ind in indicator_list])
                return f"{base_explanation} Detected indicators: {indicator_str}."
        
        # Add URL warnings if present
        if url_results:
            suspicious_urls = [r for r in url_results if r["domain_analysis"]["risk_score"] > 0.6]
            if suspicious_urls:
                return f"{base_explanation} Contains {len(suspicious_urls)} suspicious links."
        
        return base_explanation
    
    def analyze_whatsapp_screenshot(self, text: str) -> Dict[str, Any]:
        """
        Specialized analysis for WhatsApp screenshots
        
        WhatsApp screenshots have specific patterns that can be leveraged
        for more accurate scam detection.
        
        Args:
            text: Extracted text from WhatsApp screenshot
            
        Returns:
            Enhanced scam detection results
        """
        # WhatsApp-specific indicators
        whatsapp_indicators = []
        
        # Check for WhatsApp UI elements
        if "WhatsApp" in text or "online" in text or "typing" in text:
            whatsapp_indicators.append("whatsapp_interface_detected")
        
        # Check for common WhatsApp scam patterns
        whatsapp_patterns = {
            "forwarded": ["forwarded", "forwarded message"],
            "timestamp": [r'\d{1,2}:\d{2}\s*(?:AM|PM)', r'\d{1,2}:\d{2}'],
            "contact_names": [r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b']
        }
        
        for pattern_type, patterns in whatsapp_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    whatsapp_indicators.append(f"{pattern_type}_detected")
        
        # Run standard analysis
        result = self.detect_scams_in_text(text)
        
        # Enhance with WhatsApp-specific info
        result["details"]["whatsapp_indicators"] = whatsapp_indicators
        result["details"]["is_whatsapp_screenshot"] = len(whatsapp_indicators) > 0
        
        # Adjust risk score for WhatsApp context
        if whatsapp_indicators:
            # WhatsApp scams are often more sophisticated
            result["risk_score"] = min(result["risk_score"] * 1.1, 1.0)
        
        return result


# Singleton instance
_scam_text_detector_instance = None

def get_scam_text_detector() -> ScamTextDetector:
    """Get or create singleton instance"""
    global _scam_text_detector_instance
    if _scam_text_detector_instance is None:
        _scam_text_detector_instance = ScamTextDetector()
    return _scam_text_detector_instance