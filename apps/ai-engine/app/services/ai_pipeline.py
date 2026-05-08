# AYUSH WORK AREA
# Main AI Pipeline orchestrator implementing "Extract -> Analyze -> Score -> Classify" flow
# Central hub that coordinates all AI detection services and classifiers
# Implements the modular pipeline architecture described in CONTEXT.md Section 4C

import logging
import time
from typing import Dict, Any, Optional, Union
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings
from app.services.phishing_detector import get_phishing_detection_service
from app.services.ocr_service import get_ocr_service
from app.services.scoring_service import get_risk_scoring_service
from app.services.threat_service import get_threat_classification_service
from app.schemas.common import AnalysisResponse
from app.schemas.url import URLAnalysisRequest, URLAnalysisResponse
from app.schemas.ocr import OCRAnalysisRequest, OCRAnalysisResponse
from app.schemas.apk import APKAnalysisRequest, APKAnalysisResponse

logger = setup_logger("ai_pipeline")

class AIPipeline:
    """
    Main AI Pipeline orchestrator implementing the "Extract -> Analyze -> Score -> Classify" flow
    
    This class serves as the central hub that coordinates:
    1. Extract: Data extraction from various sources (URLs, images, APKs)
    2. Analyze: Application of heuristic checks and ML classification
    3. Score: Risk scoring using unified methodology
    4. Classify: Threat categorization and explanation generation
    
    The pipeline is designed to be modular and extensible for different detection types.
    """
    
    def __init__(self):
        """Initialize all AI pipeline components"""
        self.phishing_service = get_phishing_detection_service()
        self.ocr_service = get_ocr_service()
        self.scoring_service = get_risk_scoring_service()
        self.threat_service = get_threat_classification_service()
        
        logger.info("AI Pipeline initialized with all services")
    
    async def process_scan_request(
        self, 
        scan_type: str, 
        data: Union[str, Dict[str, Any]]
    ) -> AnalysisResponse:
        """
        Process a scan request through the complete AI pipeline
        
        Args:
            scan_type: Type of scan ('url', 'qr', 'ocr', 'apk')
            data: Input data (URL string, base64 image, etc.)
            
        Returns:
            AnalysisResponse with risk score and explanation
        """
        start_time = time.time()
        
        try:
            # Step 1: Extract - Prepare input for analysis
            extracted_data = await self._extract_input(scan_type, data)
            
            # Step 2: Analyze - Apply appropriate detection service
            raw_results = await self._analyze_input(scan_type, extracted_data)
            
            # Step 3: Score - Calculate risk score
            scored_results = self.scoring_service.calculate_risk_score(scan_type, raw_results)
            
            # Step 4: Classify - Generate threat classification
            classified_results = self.threat_service.classify_threat(scan_type, scored_results)
            
            # Add pipeline metadata
            classified_results.details = {
                **classified_results.details,
                "pipeline_execution_time_ms": round((time.time() - start_time) * 1000, 2),
                "pipeline_stages": ["extract", "analyze", "score", "classify"],
                "scan_type": scan_type,
                "processed_at": datetime.utcnow().isoformat()
            }
            
            logger.info(
                f"Pipeline completed for {scan_type} scan",
                extra={
                    "scan_type": scan_type,
                    "risk_score": classified_results.risk_score,
                    "category": classified_results.category,
                    "processing_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            )
            
            return classified_results
            
        except Exception as e:
            logger.error(f"Pipeline processing failed for {scan_type}: {str(e)}", exc_info=True)
            return AnalysisResponse(
                risk_score=0.5,
                category="error",
                explanation="AI pipeline processing failed. Please try again.",
                details={
                    "error": str(e),
                    "scan_type": scan_type,
                    "pipeline_stage": "error_handling",
                    "processing_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            )
    
    async def _extract_input(
        self, 
        scan_type: str, 
        data: Union[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Extract and prepare input data for analysis
        
        Args:
            scan_type: Type of scan
            data: Raw input data
            
        Returns:
            Prepared input data dictionary
        """
        logger.debug(f"Extracting input for {scan_type}")
        
        if scan_type == "url":
            if isinstance(data, str):
                return {"url": data}
            elif isinstance(data, dict) and "url" in data:
                return data
            else:
                raise ValueError("URL scan requires a URL string or dict with 'url' key")
        
        elif scan_type in ["qr", "ocr"]:
            # For QR/OCR, data should be base64 image string
            if isinstance(data, str):
                return {"image": data}
            elif isinstance(data, dict) and "image" in data:
                return data
            else:
                raise ValueError("QR/OCR scan requires base64 image data")
        
        elif scan_type == "apk":
            if isinstance(data, str):
                return {"apk_data": data}
            elif isinstance(data, dict) and "apk_data" in data:
                return data
            else:
                raise ValueError("APK scan requires APK data")
        
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")
    
    async def _analyze_input(
        self, 
        scan_type: str, 
        extracted_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Apply appropriate analysis service based on scan type
        
        Args:
            scan_type: Type of scan
            extracted_data: Prepared input data
            
        Returns:
            Raw analysis results from the appropriate service
        """
        logger.debug(f"Analyzing input for {scan_type}")
        
        if scan_type == "url":
            url = extracted_data.get("url")
            if not url:
                raise ValueError("URL is required for URL analysis")
            
            result = self.phishing_service.detect_phishing(url)
            return result.dict()
        
        elif scan_type in ["qr", "ocr"]:
            image_data = extracted_data.get("image")
            if not image_data:
                raise ValueError("Image data is required for QR/OCR analysis")
            
            result = self.ocr_service.extract_and_analyze_text(image_data)
            return result.dict()
        
        elif scan_type == "apk":
            apk_data = extracted_data.get("apk_data")
            if not apk_data:
                raise ValueError("APK data is required for APK analysis")
            
            # TODO: Implement APK analysis service
            # For now, return placeholder until APK scanner is implemented
            logger.warning("APK analysis not fully implemented yet")
            return {
                "risk_score": 0.0,
                "category": "pending",
                "explanation": "APK analysis is currently being processed. Results will be available shortly.",
                "details": {"status": "processing"}
            }
        
        else:
            raise ValueError(f"Unsupported scan type: {scan_type}")
    
    def get_pipeline_health(self) -> Dict[str, Any]:
        """
        Get health status of the AI pipeline
        
        Returns:
            Health status information
        """
        return {
            "status": "healthy",
            "service": "ai-pipeline",
            "version": "1.0.0",
            "components": {
                "phishing_service": "active",
                "ocr_service": "active",
                "scoring_service": "active",
                "threat_service": "active"
            },
            "timestamp": datetime.utcnow().isoformat(),
            "uptime": getattr(self, '_startup_time', datetime.utcnow()).timestamp()
        }
    
    def get_supported_scan_types(self) -> list:
        """
        Get list of supported scan types
        
        Returns:
            List of supported scan types
        """
        return ["url", "qr", "ocr", "apk"]


# Singleton instance for the AI pipeline
_ai_pipeline_instance: Optional[AIPipeline] = None

def get_ai_pipeline() -> AIPipeline:
    """
    Get or create singleton instance of the AI pipeline
    
    Returns:
        AIPipeline instance
    """
    global _ai_pipeline_instance
    if _ai_pipeline_instance is None:
        _ai_pipeline_instance = AIPipeline()
    return _ai_pipeline_instance


# Example usage function for testing
async def test_pipeline():
    """
    Test function to demonstrate pipeline usage
    """
    pipeline = get_ai_pipeline()
    
    # Test URL scan
    url_result = await pipeline.process_scan_request("url", "https://example.com/login")
    print(f"URL Scan Result: {url_result.risk_score} - {url_result.category}")
    
    # Test OCR scan (with sample base64 image - would be real image in practice)
    # ocr_result = await pipeline.process_scan_request("ocr", "base64_encoded_image_data_here")
    # print(f"OCR Scan Result: {ocr_result.risk_score} - {ocr_result.category}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_pipeline())