# AYUSH WORK AREA
# Threat classification service implementation
# Implements CONTEXT.md: "Threat Classification: AI-powered categorization of threats"
# Provides unified threat categorization across all detection types

import logging
import time
from typing import Dict, Any, Tuple, Optional, List
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings
from app.classifiers.risk_classifier import get_risk_classifier
from app.schemas.common import AnalysisResponse, RiskLevel
from app.schemas.url import URLAnalysisResponse
from app.schemas.ocr import OCRAnalysisResponse
from app.schemas.apk import APKAnalysisResponse

logger = setup_logger("threat_service")

class ThreatClassificationService:
    """
    Unified threat classification service
    
    This service provides consistent threat categorization across:
    - URL phishing detection
    - OCR-based scam detection
    - APK malware analysis
    - QR code analysis
    
    The service implements the threat classification methodology defined in CONTEXT.md:
    - Returns standardized threat categories
    - Supports multi-category classification
    - Provides explanation for classification decisions
    """
    
    def __init__(self):
        """Initialize threat classification service"""
        self.risk_classifier = get_risk_classifier()
        logger.info("ThreatClassificationService initialized")
    
    def classify_threat(
        self, 
        detection_type: str, 
        raw_results: Dict[str, Any]
    ) -> AnalysisResponse:
        """
        Classify threat based on detection results
        
        Args:
            detection_type: Type of detection (url, ocr, apk, qr)
            raw_results: Raw detection results
            
        Returns:
            AnalysisResponse with classified threat information
        """
        start_time = time.time()
        
        try:
            # Get appropriate classification method based on detection type
            if detection_type == "url":
                return self._classify_url_threat(raw_results)
            elif detection_type == "ocr":
                return self._classify_ocr_threat(raw_results)
            elif detection_type == "apk":
                return self._classify_apk_threat(raw_results)
            elif detection_type == "qr":
                return self._classify_qr_threat(raw_results)
            else:
                return self._create_default_classification(
                    "unknown", 
                    0.5, 
                    "Unknown threat type", 
                    "Threat type not supported", 
                    start_time
                )
                
        except Exception as e:
            logger.error(f"Threat classification failed for {detection_type}: {str(e)}", exc_info=True)
            return AnalysisResponse(
                risk_score=0.5,
                category="error",
                explanation="Failed to classify threat. Please try again.",
                details={
                    "error": str(e),
                    "detection_type": detection_type,
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            )
    
    def _classify_url_threat(self, results: Dict[str, Any]) -> AnalysisResponse:
        """
        Classify URL threat
        
        Args:
            results: URL detection results
            
        Returns:
            AnalysisResponse with classified threat
        """
        # Use unified risk classifier for URL analysis
        url = results.get("details", {}).get("original_url", "")
        if url:
            risk_result = self.risk_classifier.assess_url_risk(url)
            
            return AnalysisResponse(
                risk_score=risk_result["risk_score"],
                category=risk_result["risk_level"],
                explanation=risk_result["explanation"],
                details={
                    **results.get("details", {}),
                    "threat_classification": risk_result["detailed_results"],
                    "risk_level": risk_result["risk_level"],
                    "detection_type": "url"
                }
            )
        
        # Fallback to direct results
        risk_score = results.get("risk_score", 0.5)
        category = results.get("category", "unknown")
        explanation = results.get("explanation", "URL analysis completed")
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **results.get("details", {}),
                "risk_level": self._map_risk_score_to_level(risk_score),
                "detection_type": "url"
            }
        )
    
    def _classify_ocr_threat(self, results: Dict[str, Any]) -> AnalysisResponse:
        """
        Classify OCR-based threat
        
        Args:
            results: OCR detection results
            
        Returns:
            AnalysisResponse with classified threat
        """
        # Extract text for unified classification
        extracted_text = results.get("details", {}).get("text_preview", "")
        if extracted_text:
            # Use unified risk classifier for text analysis
            risk_result = self.risk_classifier.assess_text_risk(extracted_text)
            
            return AnalysisResponse(
                risk_score=risk_result["risk_score"],
                category=risk_result["risk_level"],
                explanation=risk_result["explanation"],
                details={
                    **results.get("details", {}),
                    "threat_classification": risk_result["detailed_results"],
                    "risk_level": risk_result["risk_level"],
                    "detection_type": "ocr"
                }
            )
        
        # Fallback
        risk_score = results.get("risk_score", 0.5)
        category = results.get("category", "unknown")
        explanation = results.get("explanation", "OCR analysis completed")
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **results.get("details", {}),
                "risk_level": self._map_risk_score_to_level(risk_score),
                "detection_type": "ocr"
            }
        )
    
    def _classify_apk_threat(self, results: Dict[str, Any]) -> AnalysisResponse:
        """
        Classify APK threat
        
        Args:
            results: APK detection results
            
        Returns:
            AnalysisResponse with classified threat
        """
        # APK classification is primarily based on static analysis
        risk_score = results.get("risk_score", 0.5)
        category = results.get("category", "unknown")
        explanation = results.get("explanation", "APK analysis completed")
        
        # Map to standard risk levels
        risk_level = self._map_risk_score_to_level(risk_score)
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **results.get("details", {}),
                "risk_level": risk_level,
                "detection_type": "apk"
            }
        )
    
    def _classify_qr_threat(self, results: Dict[str, Any]) -> AnalysisResponse:
        """
        Classify QR threat
        
        Args:
            results: QR detection results
            
        Returns:
            AnalysisResponse with classified threat
        """
        # Extract QR payload for classification
        qr_payload = results.get("details", {}).get("qr_payload", "")
        if qr_payload:
            # Classify based on payload type
            if qr_payload.startswith(("http://", "https://")):
                # URL payload - use URL classification
                risk_result = self.risk_classifier.assess_url_risk(qr_payload)
            else:
                # Text payload - use text classification
                risk_result = self.risk_classifier.assess_text_risk(qr_payload)
            
            return AnalysisResponse(
                risk_score=risk_result["risk_score"],
                category=risk_result["risk_level"],
                explanation=risk_result["explanation"],
                details={
                    **results.get("details", {}),
                    "threat_classification": risk_result["detailed_results"],
                    "risk_level": risk_result["risk_level"],
                    "detection_type": "qr"
                }
            )
        
        # Fallback
        risk_score = results.get("risk_score", 0.5)
        category = results.get("category", "unknown")
        explanation = results.get("explanation", "QR analysis completed")
        
        return AnalysisResponse(
            risk_score=risk_score,
            category=category,
            explanation=explanation,
            details={
                **results.get("details", {}),
                "risk_level": self._map_risk_score_to_level(risk_score),
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
    
    def _create_default_classification(
        self, 
        category: str, 
        risk_score: float, 
        title: str, 
        explanation: str, 
        start_time: float
    ) -> AnalysisResponse:
        """
        Create default threat classification response
        
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
_threat_service_instance = None

def get_threat_classification_service() -> ThreatClassificationService:
    """Get or create singleton instance"""
    global _threat_service_instance
    if _threat_service_instance is None:
        _threat_service_instance = ThreatClassificationService()
    return _threat_service_instance