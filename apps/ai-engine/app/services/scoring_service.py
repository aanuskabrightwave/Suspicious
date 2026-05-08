# AYUSH WORK AREA
# Risk scoring service implementation
# Implements CONTEXT.md: "Scoring System: Returns a RiskScore (0.0 - 1.0) with Explanation string"
# Provides unified risk assessment across all detection types

import logging
import time
from typing import Dict, Any, Tuple, Optional, List
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings
from app.schemas.common import AnalysisResponse, RiskLevel
from app.schemas.url import URLAnalysisResponse
from app.schemas.ocr import OCRAnalysisResponse
from app.schemas.apk import APKAnalysisResponse

logger = setup_logger("scoring_service")

class RiskScoringService:
    """
    Unified risk scoring service for all detection types
    
    This service provides consistent risk scoring across:
    - URL phishing detection
    - OCR-based scam detection
    - APK malware analysis
    - QR code analysis
    
    The service implements the scoring methodology defined in CONTEXT.md:
    - Returns a RiskScore (0.0-1.0)
    - Provides user-friendly Explanation strings
    - Supports category-based classification
    """
    
    def __init__(self):
        """Initialize scoring service"""
        logger.info("RiskScoringService initialized")
    
    def calculate_risk_score(
        self, 
        detection_type: str, 
        raw_results: Dict[str, Any]
    ) -> AnalysisResponse:
        """
        Calculate unified risk score for any detection type
        
        Args:
            detection_type: Type of detection (url, ocr, apk, qr)
            raw_results: Raw detection results
            
        Returns:
            AnalysisResponse with standardized risk assessment
        """
        start_time = time.time()
        
        try:
            # Get appropriate scoring method based on detection type
            if detection_type == "url":
                return self._score_url_detection(raw_results)
            elif detection_type == "ocr":
                return self._score_ocr_detection(raw_results)
            elif detection_type == "apk":
                return self._score_apk_detection(raw_results)
            elif detection_type == "qr":
                return self._score_qr_detection(raw_results)
            else:
                return self._create_default_response(
                    "unknown", 
                    0.5, 
                    "Unknown detection type", 
                    "Detection type not supported", 
                    start_time
                )
                
        except Exception as e:
            logger.error(f"Risk scoring failed for {detection_type}: {str(e)}", exc_info=True)
            return AnalysisResponse(
                risk_score=0.5,
                category="error",
                explanation="Failed to calculate risk score. Please try again.",
                details={
                    "error": str(e),
                    "detection_type": detection_type,
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            )
    
    def _score_url_detection(self, results: Dict[str, Any]) -> AnalysisResponse:
        """
        Score URL phishing detection results
        
        Args:
            results: URL detection results
            
        Returns:
            AnalysisResponse with scored results
        """
        # Extract key metrics
        risk_score = results.get("risk_score", 0.5)
        category = results.get("category", "unknown")
        explanation = results.get("explanation", "URL analysis completed")
        details = results.get("details", {})
        
        # Normalize risk score to 0-1 range
        risk_score = max(0.0, min(1.0, risk_score))
        
        # Determine risk level
        risk_level = self._map_risk_score_to_level(risk_score)
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **details,
                "risk_level": risk_level,
                "detection_type": "url"
            }
        )
    
    def _score_ocr_detection(self, results: Dict[str, Any]) -> AnalysisResponse:
        """
        Score OCR-based scam detection results
        
        Args:
            results: OCR detection results
            
        Returns:
            AnalysisResponse with scored results
        """
        # Extract key metrics
        risk_score = results.get("risk_score", 0.5)
        category = results.get("category", "unknown")
        explanation = results.get("explanation", "OCR analysis completed")
        details = results.get("details", {})
        
        # Normalize risk score to 0-1 range
        risk_score = max(0.0, min(1.0, risk_score))
        
        # Adjust for text quality
        text_metadata = details.get("text_extraction", {})
        text_confidence = text_metadata.get("confidence", 1.0)
        
        # Reduce risk score if text extraction confidence is low
        if text_confidence < 0.5:
            risk_score *= 0.7
        
        # Determine risk level
        risk_level = self._map_risk_score_to_level(risk_score)
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **details,
                "risk_level": risk_level,
                "detection_type": "ocr"
            }
        )
    
    def _score_apk_detection(self, results: Dict[str, Any]) -> AnalysisResponse:
        """
        Score APK malware detection results
        
        Args:
            results: APK detection results
            
        Returns:
            AnalysisResponse with scored results
        """
        # Extract key metrics
        risk_score = results.get("risk_score", 0.5)
        category = results.get("category", "unknown")
        explanation = results.get("explanation", "APK analysis completed")
        details = results.get("details", {})
        
        # Normalize risk score to 0-1 range
        risk_score = max(0.0, min(1.0, risk_score))
        
        # Adjust for analysis completeness
        apk_analysis = details.get("manifest_analysis", {})
        if apk_analysis.get("error"):
            # Incomplete analysis reduces confidence
            risk_score *= 0.8
        
        # Determine risk level
        risk_level = self._map_risk_score_to_level(risk_score)
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **details,
                "risk_level": risk_level,
                "detection_type": "apk"
            }
        )
    
    def _score_qr_detection(self, results: Dict[str, Any]) -> AnalysisResponse:
        """
        Score QR code detection results
        
        Args:
            results: QR detection results
            
        Returns:
            AnalysisResponse with scored results
        """
        # Extract key metrics
        risk_score = results.get("risk_score", 0.5)
        category = results.get("category", "unknown")
        explanation = results.get("explanation", "QR analysis completed")
        details = results.get("details", {})
        
        # Normalize risk score to 0-1 range
        risk_score = max(0.0, min(1.0, risk_score))
        
        # Adjust for payload type
        qr_payload = details.get("qr_payload", "")
        if qr_payload.startswith(("http://", "https://")):
            # URL payloads get additional scrutiny
            risk_score = min(risk_score * 1.1, 1.0)
        
        # Determine risk level
        risk_level = self._map_risk_score_to_level(risk_score)
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **details,
                "risk_level": risk_level,
                "detection_type": "qr"
            }
        )
    
    def _map_risk_score_to_level(self, risk_score: float) -> str:
        """
        Map risk score to categorical risk level
        
        Args:
            risk_score: Risk score 0.0-1.0
            
        Returns:
            Risk level string
        """
        if risk_score < 0.2:
            return "safe"
        elif risk_score < 0.4:
            return "low"
        elif risk_score < 0.6:
            return "medium"
        elif risk_score < 0.8:
            return "high"
        else:
            return "critical"
    
    def _create_default_response(
        self, 
        category: str, 
        risk_score: float, 
        title: str, 
        explanation: str, 
        start_time: float
    ) -> AnalysisResponse:
        """
        Create default analysis response
        
        Args:
            category: Threat category
            risk_score: Risk score
            title: Title for the response
            explanation: User-friendly explanation
            start_time: Start time for processing time calculation
            
        Returns:
            AnalysisResponse object
        """
        processing_time_ms = round((time.time() - start_time) * 1000, 2)
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                "title": title,
                "processing_time_ms": processing_time_ms,
                "risk_level": self._map_risk_score_to_level(risk_score),
                "timestamp": datetime.utcnow().isoformat()
            }
        )


# Singleton instance
_scoring_service_instance = None

def get_risk_scoring_service() -> RiskScoringService:
    """Get or create singleton instance"""
    global _scoring_service_instance
    if _scoring_service_instance is None:
        _scoring_service_instance = RiskScoringService()
    return _scoring_service_instance