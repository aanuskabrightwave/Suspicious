# AYUSH WORK AREA
# Phishing detection service implementation
# Implements CONTEXT.md: "AI Engine: Modular Pipeline (Extract -> Analyze -> Score -> Classify)"
# Handles URL phishing detection with heuristic + ML hybrid approach

import logging
import time
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings
from app.classifiers.phishing_classifier import get_phishing_classifier
from app.heuristics.domain_checks import get_domain_checker
from app.heuristics.keyword_checks import get_keyword_checker
from app.heuristics.redirect_checks import get_redirect_checker
from app.schemas.common import AnalysisResponse
from app.schemas.url import URLAnalysisRequest, URLAnalysisResponse

logger = setup_logger("phishing_detector")

class PhishingDetectionService:
    """
    Comprehensive phishing detection service
    
    This service implements the core business logic for URL phishing detection:
    1. Initial heuristic checks for fast, high-confidence detections
    2. ML classification for complex cases where heuristics are inconclusive
    3. Risk scoring and explanation generation
    4. Caching integration for performance optimization
    
    The service follows the "Extract -> Analyze -> Score -> Classify" pipeline
    described in the CONTEXT.md architecture.
    """
    
    def __init__(self):
        """Initialize phishing detection components"""
        self.phishing_classifier = get_phishing_classifier()
        self.domain_checker = get_domain_checker()
        self.keyword_checker = get_keyword_checker()
        self.redirect_checker = get_redirect_checker()
        logger.info("PhishingDetectionService initialized")
    
    def detect_phishing(self, url: str) -> AnalysisResponse:
        """
        Detect phishing in a URL
        
        Args:
            url: URL to analyze
            
        Returns:
            AnalysisResponse with risk score and explanation
        """
        start_time = time.time()
        
        try:
            # Step 1: Quick heuristic checks (fast path)
            heuristic_result, heuristic_confidence = self._run_heuristic_checks(url)
            
            # If heuristic confidence is high, use it directly
            if heuristic_confidence >= settings.HEURISTIC_CONFIDENCE_THRESHOLD:
                return self._create_analysis_response(
                    url, 
                    heuristic_result["risk_score"], 
                    heuristic_result["category"],
                    heuristic_result["explanation"],
                    heuristic_result,
                    start_time
                )
            
            # Step 2: ML classification (slower but more accurate)
            ml_score, ml_confidence, ml_metadata = self.phishing_classifier.predict(url)
            
            # Step 3: Combine heuristic and ML results
            combined_score = self._combine_scores(
                heuristic_result["risk_score"], 
                ml_score, 
                heuristic_confidence, 
                ml_confidence
            )
            
            # Determine final category
            final_category = self._determine_final_category(combined_score, ml_score, heuristic_result["category"])
            
            # Generate explanation
            explanation = self._generate_explanation(
                combined_score, 
                final_category, 
                heuristic_result, 
                ml_metadata
            )
            
            return self._create_analysis_response(
                url, 
                combined_score, 
                final_category, 
                explanation, 
                {
                    "heuristic_result": heuristic_result,
                    "ml_result": {
                        "score": ml_score,
                        "confidence": ml_confidence,
                        "metadata": ml_metadata
                    }
                },
                start_time
            )
            
        except Exception as e:
            logger.error(f"Phishing detection failed for {url}: {str(e)}", exc_info=True)
            return AnalysisResponse(
                risk_score=0.5,
                category="error",
                explanation="Failed to analyze URL. Please try again.",
                details={
                    "error": str(e),
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            )
    
    def _run_heuristic_checks(self, url: str) -> Tuple[Dict[str, Any], float]:
        """
        Run fast heuristic checks for phishing detection
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (heuristic_result, confidence)
        """
        try:
            # Domain analysis
            domain_result = self.domain_checker.analyze_domain(url)
            
            # Keyword analysis
            keyword_result = self.keyword_checker.analyze_url(url)
            
            # Redirect analysis (lightweight version)
            redirect_result = self.redirect_checker.check_redirect_safety(url)
            
            # Calculate overall heuristic risk
            risk_score = self._calculate_heuristic_risk(
                domain_result, 
                keyword_result, 
                redirect_result
            )
            
            # Determine category
            category = self._determine_heuristic_category(domain_result, keyword_result)
            
            # Generate explanation
            explanation = self._generate_heuristic_explanation(risk_score, category, domain_result, keyword_result)
            
            # More sophisticated confidence calculation
            indicator_count = (
                len(domain_result.get("indicators", [])) +
                len(keyword_result.get("indicators", []))
            )
            confidence = min(0.8 + (indicator_count * 0.05), 0.95)
            
            # Boost confidence for high-risk indicators
            if risk_score > 0.7:
                confidence = min(confidence * 1.2, 0.99)
            
            return {
                "risk_score": risk_score,
                "category": category,
                "explanation": explanation,
                "domain_analysis": domain_result,
                "keyword_analysis": keyword_result,
                "redirect_analysis": redirect_result
            }, confidence
            
        except Exception as e:
            logger.error(f"Heuristic checks failed for {url}: {str(e)}")
            # Return neutral result on error
            return {
                "risk_score": 0.5,
                "category": "unknown",
                "explanation": "Heuristic analysis failed",
                "domain_analysis": {},
                "keyword_analysis": {},
                "redirect_analysis": {}
            }, 0.3
    
    def _calculate_heuristic_risk(
        self, 
        domain_result: Dict[str, Any], 
        keyword_result: Dict[str, Any], 
        redirect_result: Dict[str, Any]
    ) -> float:
        """
        Calculate risk score from heuristic analysis
        
        Args:
            domain_result: Domain analysis results
            keyword_result: Keyword analysis results
            redirect_result: Redirect analysis results
            
        Returns:
            Risk score 0.0-1.0
        """
        score = 0.0
        
        # Domain-based risk
        domain_risk = domain_result.get("risk_score", 0.0)
        score += domain_risk * 0.4
        
        # Keyword-based risk
        keyword_risk = keyword_result.get("risk_score", 0.0)
        score += keyword_risk * 0.3
        
        # Redirect-based risk
        if redirect_result.get("risk_level") == "high":
            score += 0.3
        elif redirect_result.get("risk_level") == "medium":
            score += 0.2
        
        # Indicator-based risk
        domain_indicators = domain_result.get("indicators", [])
        keyword_indicators = keyword_result.get("indicators", [])
        total_indicators = len(domain_indicators) + len(keyword_indicators)
        
        # Each indicator adds 0.05 to risk score (capped at 0.2)
        score += min(total_indicators * 0.05, 0.2)
        
        # Normalize to 0-1 range
        return min(score, 1.0)
    
    def _determine_heuristic_category(
        self, 
        domain_result: Dict[str, Any], 
        keyword_result: Dict[str, Any]
    ) -> str:
        """
        Determine threat category from heuristic analysis
        
        Args:
            domain_result: Domain analysis results
            keyword_result: Keyword analysis results
            
        Returns:
            Threat category string
        """
        # Check for high-risk indicators
        domain_indicators = domain_result.get("indicators", [])
        keyword_indicators = keyword_result.get("indicators", [])
        
        # Look for banking-related indicators
        banking_keywords = ['otp', 'pin', 'password', 'bank', 'account']
        has_banking_indicators = any(
            any(kw in str(ind).lower() for kw in banking_keywords)
            for ind in domain_indicators + keyword_indicators
        )
        
        if has_banking_indicators:
            return "banking_phishing"
        
        # Check for general phishing indicators
        phishing_indicators = [
            'homograph', 'suspicious_tld', 'ip_address', 
            'known_malicious', 'redirect'
        ]
        
        if any(any(indicator in str(ind).lower() for indicator in phishing_indicators) 
               for ind in domain_indicators + keyword_indicators):
            return "phishing"
        
        # Check for suspicious activity
        if domain_result.get("risk_score", 0) > 0.6 or keyword_result.get("risk_score", 0) > 0.6:
            return "suspicious"
        
        return "safe"
    
    def _generate_heuristic_explanation(
        self, 
        risk_score: float, 
        category: str, 
        domain_result: Dict[str, Any], 
        keyword_result: Dict[str, Any]
    ) -> str:
        """
        Generate explanation for heuristic analysis
        
        Args:
            risk_score: Calculated risk score
            category: Threat category
            domain_result: Domain analysis results
            keyword_result: Keyword analysis results
            
        Returns:
            Human-readable explanation
        """
        if risk_score < 0.3:
            return "This URL appears safe. No significant phishing indicators detected."
        
        explanations = {
            "banking_phishing": "This URL shows strong indicators of a fake banking site attempting to steal your login credentials.",
            "phishing": "This URL shows strong indicators of a phishing attempt. Avoid entering any personal information.",
            "suspicious": "This URL has suspicious characteristics that warrant caution.",
            "safe": "This URL appears safe. No significant security concerns detected."
        }
        
        base_explanation = explanations.get(category, "This URL has security concerns that require attention.")
        
        # Add specific indicators
        indicators = []
        
        # Domain indicators
        domain_inds = domain_result.get("indicators", [])
        for ind in domain_inds[:2]:
            if isinstance(ind, dict):
                indicators.append(ind.get("description", ""))
            else:
                indicators.append(str(ind))
        
        # Keyword indicators
        keyword_inds = keyword_result.get("indicators", [])
        for ind in keyword_inds[:2]:
            if isinstance(ind, dict):
                indicators.append(ind.get("description", ""))
            else:
                indicators.append(str(ind))
        
        if indicators:
            indicator_str = ", ".join([f'"{ind}"' for ind in indicators if ind])
            return f"{base_explanation} Detected: {indicator_str}."
        
        return base_explanation
    
    def _combine_scores(
        self, 
        heuristic_score: float, 
        ml_score: float, 
        heuristic_confidence: float, 
        ml_confidence: float
    ) -> float:
        """
        Combine heuristic and ML scores
        
        Args:
            heuristic_score: Heuristic-based risk score
            ml_score: ML classifier risk score
            heuristic_confidence: Heuristic confidence level
            ml_confidence: ML confidence level
            
        Returns:
            Combined risk score
        """
        # Weight heuristic score higher if ML confidence is low
        if ml_confidence < 0.5:
            return heuristic_score * 0.7 + ml_score * 0.3
        
        # Weight ML score higher if heuristic confidence is low
        if heuristic_confidence < 0.5:
            return heuristic_score * 0.3 + ml_score * 0.7
        
        # Otherwise, use balanced weighting
        return heuristic_score * 0.4 + ml_score * 0.6
    
    def _determine_final_category(
        self, 
        combined_score: float, 
        ml_score: float, 
        heuristic_category: str
    ) -> str:
        """
        Determine final threat category
        
        Args:
            combined_score: Combined risk score
            ml_score: ML classifier score
            heuristic_category: Heuristic-based category
            
        Returns:
            Final threat category
        """
        if combined_score >= 0.8:
            return "phishing"
        elif combined_score >= 0.6:
            return "suspicious"
        elif combined_score >= 0.4:
            return "caution"
        else:
            return "safe"
    
    def _generate_explanation(
        self, 
        risk_score: float, 
        category: str, 
        heuristic_result: Dict[str, Any], 
        ml_metadata: Dict[str, Any]
    ) -> str:
        """
        Generate final explanation combining heuristic and ML results
        
        Args:
            risk_score: Final risk score
            category: Final threat category
            heuristic_result: Heuristic analysis results
            ml_metadata: ML classification metadata
            
        Returns:
            Human-readable explanation
        """
        if risk_score < 0.3:
            return "This URL appears safe. No significant phishing indicators detected."
        
        explanations = {
            "phishing": "This URL shows strong indicators of a phishing attempt. Avoid entering any personal information.",
            "suspicious": "This URL has suspicious characteristics that warrant caution.",
            "caution": "This URL has some concerning elements. Proceed with care.",
            "safe": "This URL appears safe. No significant security concerns detected."
        }
        
        base_explanation = explanations.get(category, "This URL has security concerns that require attention.")
        
        # Add ML-specific details
        ml_details = []
        if ml_metadata.get("confidence", 0) > 0.7:
            ml_details.append(f"ML model confidence: {ml_metadata['confidence']:.2f}")
        
        # Add heuristic details
        heuristic_details = []
        domain_indicators = heuristic_result.get("domain_analysis", {}).get("indicators", [])
        keyword_indicators = heuristic_result.get("keyword_analysis", {}).get("indicators", [])
        
        if domain_indicators:
            heuristic_details.append(f"Domain issues: {len(domain_indicators)} indicators")
        if keyword_indicators:
            heuristic_details.append(f"Text issues: {len(keyword_indicators)} indicators")
        
        if ml_details or heuristic_details:
            details = " | ".join(ml_details + heuristic_details)
            return f"{base_explanation} ({details})"
        
        return base_explanation
    
    def _create_analysis_response(
        self, 
        url: str, 
        risk_score: float, 
        category: str, 
        explanation: str, 
        details: Dict[str, Any], 
        start_time: float
    ) -> AnalysisResponse:
        """
        Create standardized analysis response
        
        Args:
            url: Original URL
            risk_score: Calculated risk score
            category: Threat category
            explanation: User-friendly explanation
            details: Technical details
            start_time: Start time for processing time calculation
            
        Returns:
            AnalysisResponse object
        """
        # Calculate processing time
        processing_time_ms = round((time.time() - start_time) * 1000, 2)
        
        # Determine risk level for UI display
        risk_level = "safe"
        if risk_score >= 0.8:
            risk_level = "critical"
        elif risk_score >= 0.6:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        elif risk_score >= 0.2:
            risk_level = "low"
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **details,
                "processing_time_ms": processing_time_ms,
                "risk_level": risk_level,
                "url": url,
                "timestamp": datetime.utcnow().isoformat()
            }
        )


# Singleton instance
_phishing_detector_instance = None

def get_phishing_detection_service() -> PhishingDetectionService:
    """Get or create singleton instance"""
    global _phishing_detector_instance
    if _phishing_detector_instance is None:
        _phishing_detector_instance = PhishingDetectionService()
    return _phishing_detector_instance