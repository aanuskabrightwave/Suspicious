# AYUSH WORK AREA
# OCR Pipeline implementation for scam detection in images
# Follows the Extract -> Analyze -> Score -> Classify architecture pattern
# Integrates with preprocessing and heuristic services

from typing import Dict, Any, Optional
import logging
import base64
from io import BytesIO

# Local imports
from services.preprocessing import ImagePreprocessor
from services.ocr_service import OCRService
from services.heuristic_engine import HeuristicEngine
from services.risk_scoring import RiskScorer

logger = logging.getLogger("ai_engine")

class OCRPipeline:
    """
    OCR-based scam detection pipeline
    
    This pipeline handles the complete flow for analyzing images (QR codes, screenshots, etc.)
    to detect potential scams using a combination of:
    1. Image preprocessing (OpenCV)
    2. Text extraction (Tesseract OCR)
    3. Heuristic analysis (scam keywords, patterns)
    4. Risk scoring and classification
    
    The pipeline is designed to be efficient while maintaining high detection accuracy.
    """
    
    def __init__(self):
        """Initialize the OCR pipeline components"""
        self.preprocessor = ImagePreprocessor()
        self.ocr_service = OCRService()
        self.heuristic_engine = HeuristicEngine()
        self.risk_scorer = RiskScorer()
        logger.info("OCR Pipeline initialized")
    
    async def execute(self, image_data: str) -> Dict[str, Any]:
        """
        Execute the complete OCR analysis pipeline
        
        Args:
            image_data: Base64 encoded image data
            
        Returns:
            Dictionary containing analysis results with keys:
                - risk_score: Float between 0.0 and 1.0
                - category: Detected threat category
                - explanation: User-friendly explanation of the risk
                - details: Additional technical details
        
        Raises:
            ValueError: If image processing fails
        """
        try:
            # 1. Decode and preprocess the image
            image_bytes = self._decode_base64(image_data)
            processed_image = await self.preprocessor.process(image_bytes)
            
            # 2. Extract text using OCR
            extracted_text = await self.ocr_service.extract_text(processed_image)
            
            # 3. Analyze extracted text for scam indicators
            analysis_results = self.heuristic_engine.analyze_text(extracted_text)
            
            # 4. Generate risk score and classification
            risk_result = self.risk_scorer.calculate_ocr_risk(
                extracted_text, 
                analysis_results
            )
            
            # 5. Format final result
            return self._format_result(risk_result, extracted_text, analysis_results)
            
        except Exception as e:
            logger.error(f"OCR pipeline execution failed: {str(e)}", exc_info=True)
            # Return a safe default result in case of failure
            return {
                "risk_score": 0.0,
                "category": "error",
                "explanation": "Failed to analyze the image. Please try again.",
                "details": {"error": str(e)}
            }
    
    def _decode_base64(self, image_data: str) -> bytes:
        """Decode base64 image data to raw bytes"""
        try:
            # Remove data URL prefix if present (e.g., "data:image/png;base64,")
            if ',' in image_data:
                image_data = image_data.split(',')[1]
            
            return base64.b64decode(image_data)
        except Exception as e:
            logger.error(f"Base64 decoding failed: {str(e)}")
            raise ValueError("Invalid base64 image data") from e
    
    def _format_result(
        self, 
        risk_result: Dict[str, Any], 
        extracted_text: str,
        analysis_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Format the final analysis result for API response"""
        return {
            "risk_score": risk_result["score"],
            "category": risk_result["category"],
            "explanation": self._generate_explanation(
                risk_result["score"], 
                risk_result["category"],
                analysis_results
            ),
            "details": {
                "extracted_text": extracted_text[:500] + "..." if len(extracted_text) > 500 else extracted_text,
                "scam_indicators": analysis_results["indicators"],
                "confidence": risk_result["confidence"]
            }
        }
    
    def _generate_explanation(
        self, 
        risk_score: float, 
        category: str,
        analysis_results: Dict[str, Any]
    ) -> str:
        """Generate user-friendly explanation based on risk score and category"""
        if risk_score < 0.3:
            return "This content appears safe. No scam indicators were detected."
        
        # Generate category-specific explanations
        explanations = {
            "banking_scam": "This message contains suspicious banking requests. Legitimate banks never ask for your PIN or OTP via SMS or WhatsApp.",
            "investment_scam": "This appears to be an investment scam promising unrealistic returns. Be cautious of 'get rich quick' schemes.",
            "qr_phishing": "This QR code leads to a suspicious website that may attempt to steal your personal information.",
            "account_verification": "This is likely a fake account verification request designed to steal your login credentials.",
            "urgent_action": "This message creates false urgency to trick you into taking immediate action without thinking."
        }
        
        # Default explanation if category not found
        base_explanation = explanations.get(
            category, 
            "This content contains indicators of a potential scam. Be cautious before taking any action."
        )
        
        # Add specific indicators if present
        indicators = analysis_results["indicators"]
        if indicators:
            indicator_list = ", ".join([f'"{ind}"' for ind in indicators[:3]])
            return f"{base_explanation} Detected scam indicators: {indicator_list}."
        
        return base_explanation