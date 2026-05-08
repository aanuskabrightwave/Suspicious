# AYUSH WORK AREA
# OCR service implementation for scam detection
# Implements CONTEXT.md: "OCR Pipeline: Extract -> Analyze -> Score -> Classify"
# Handles text extraction from images and scam detection in extracted content

import logging
import time
from typing import Dict, Any, Tuple, Optional
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings
from app.ocr.image_text import get_image_text_extractor
from app.ocr.scam_text_detector import get_scam_text_detector
from app.schemas.common import AnalysisResponse
from app.schemas.ocr import OCRAnalysisRequest, OCRAnalysisResponse

logger = setup_logger("ocr_service")

class OCRService:
    """
    OCR service for text extraction and scam detection
    
    This service implements:
    1. Image preprocessing for optimal OCR results
    2. Text extraction using Tesseract OCR
    2. Scam detection in extracted text
    3. Risk scoring and explanation generation
    
    The service follows the "Extract -> Analyze -> Score -> Classify" pipeline
    described in the CONTEXT.md architecture.
    """
    
    def __init__(self):
        """Initialize OCR service components"""
        self.image_text_extractor = get_image_text_extractor()
        self.scam_text_detector = get_scam_text_detector()
        logger.info("OCRService initialized")
    
    def extract_and_analyze_text(self, image_data: str) -> AnalysisResponse:
        """
        Extract text from image and analyze for scams
        
        Args:
            image_data: Base64-encoded image data
            
        Returns:
            AnalysisResponse with risk score and explanation
        """
        start_time = time.time()
        
        try:
            # Step 1: Extract text from image
            extracted_text, text_metadata = self.image_text_extractor.extract_text_from_image(image_data)
            
            # Step 2: Analyze extracted text for scams
            scam_result = self.scam_text_detector.detect_scams_in_text(extracted_text)
            
            # Step 3: Calculate overall risk score
            risk_score, category, explanation = self._calculate_overall_risk(
                extracted_text, 
                scam_result, 
                text_metadata
            )
            
            # Step 4: Create analysis response
            return self._create_analysis_response(
                extracted_text, 
                risk_score, 
                category, 
                explanation, 
                {
                    "text_extraction": text_metadata,
                    "scam_detection": scam_result
                },
                start_time
            )
            
        except Exception as e:
            logger.error(f"OCR analysis failed: {str(e)}", exc_info=True)
            return AnalysisResponse(
                risk_score=0.5,
                category="error",
                explanation="Failed to analyze image. Please try again with a clearer image.",
                details={
                    "error": str(e),
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            )
    
    def analyze_text_only(self, text: str) -> AnalysisResponse:
        """
        Analyze text for scams without OCR extraction
        
        Args:
            text: Text to analyze
            
        Returns:
            AnalysisResponse with risk score and explanation
        """
        start_time = time.time()
        
        try:
            # Analyze text for scams
            scam_result = self.scam_text_detector.detect_scams_in_text(text)
            
            # Calculate risk score
            risk_score, category, explanation = self._calculate_overall_risk(
                text, 
                scam_result, 
                {"confidence": 1.0}
            )
            
            return self._create_analysis_response(
                text, 
                risk_score, 
                category, 
                explanation, 
                {"scam_detection": scam_result},
                start_time
            )
            
        except Exception as e:
            logger.error(f"Text analysis failed: {str(e)}", exc_info=True)
            return AnalysisResponse(
                risk_score=0.5,
                category="error",
                explanation="Failed to analyze text. Please try again.",
                details={
                    "error": str(e),
                    "analysis_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            )
    
    def _calculate_overall_risk(
        self, 
        extracted_text: str, 
        scam_result: Dict[str, Any], 
        text_metadata: Dict[str, Any]
    ) -> Tuple[float, str, str]:
        """
        Calculate overall risk score from text analysis
        
        Args:
            extracted_text: Extracted text from image
            scam_result: Scam detection results
            text_metadata: Text extraction metadata
            
        Returns:
            Tuple of (risk_score, category, explanation)
        """
        # Base risk from scam detection
        risk_score = scam_result["risk_score"]
        
        # Adjust by text quality confidence
        text_confidence = text_metadata.get("confidence", 1.0)
        if text_confidence < 0.5:
            # Low confidence in text extraction reduces reliability
            risk_score *= 0.7
        
        # Boost for high-risk indicators
        if risk_score > 0.7:
            # High-risk cases get slightly higher scores
            risk_score = min(risk_score * 1.1, 1.0)
        
        # Determine category
        category = scam_result["category"]
        
        # Generate explanation
        explanation = scam_result["explanation"]
        
        return risk_score, category, explanation
    
    def _create_analysis_response(
        self, 
        extracted_text: str, 
        risk_score: float, 
        category: str, 
        explanation: str, 
        details: Dict[str, Any], 
        start_time: float
    ) -> AnalysisResponse:
        """
        Create standardized analysis response
        
        Args:
            extracted_text: Extracted text
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
        
        # Determine risk level
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
                "text_preview": extracted_text[:200] + "..." if len(extracted_text) > 200 else extracted_text,
                "timestamp": datetime.utcnow().isoformat()
            }
        )


# Singleton instance
_ocr_service_instance = None

def get_ocr_service() -> OCRService:
    """Get or create singleton instance"""
    global _ocr_service_instance
    if _ocr_service_instance is None:
        _ocr_service_instance = OCRService()
    return _ocr_service_instance