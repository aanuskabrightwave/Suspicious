# AYUSH WORK AREA
# OCR-based scam detection endpoint
# Extracts text from images/screenshots and analyzes for scam patterns
# Critical for detecting WhatsApp/SMS scams per CONTEXT.md

from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File
from typing import Dict, Any, Optional, List
import logging
import time

# Local imports
from app.schemas.ocr import OCRAnalysisRequest, OCRAnalysisResponse
from app.schemas.common import AnalysisResponse
from app.pipelines.ocr_pipeline import OCRPipeline
from app.utils.validators import validate_base64_image
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("ocr_scan")

# Create router for OCR-specific endpoints
router = APIRouter()

# Initialize OCR pipeline
def get_ocr_pipeline() -> OCRPipeline:
    """Dependency injection for OCR pipeline"""
    return OCRPipeline()

@router.post("/ocr", response_model=AnalysisResponse)
async def analyze_ocr(
    request: OCRAnalysisRequest,
    pipeline: OCRPipeline = Depends(get_ocr_pipeline)
) -> AnalysisResponse:
    """
    Analyze an image for scam content using OCR
    
    This endpoint is critical for detecting scams in:
    - WhatsApp screenshots
    - SMS messages
    - Email screenshots
    - Any image containing text
    
    Flow:
    1. Validate and preprocess image
    2. Extract text using Tesseract OCR
    3. Run NLP analysis on extracted text
    4. Detect scam keywords and patterns
    5. Calculate risk score and generate explanation
    
    Args:
        request: OCRAnalysisRequest with base64 image
        pipeline: Injected OCR pipeline
    
    Returns:
        AnalysisResponse with scam detection results
    
    Raises:
        HTTPException: If image is invalid or OCR fails
    
    Security Note: OCR is computationally expensive. Rate limiting
    should be enforced at the API gateway level.
    """
    start_time = time.time()
    image_data = request.image.strip()
    
    # 1. Validate input
    if not image_data:
        logger.warning("OCR analysis request received with empty image")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Image data is required"
        )
    
    # 2. Validate image format
    if not validate_base64_image(image_data):
        logger.warning("Invalid base64 image format for OCR")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid image format. Expected base64-encoded PNG/JPEG"
        )
    
    # Check size
    image_size_mb = len(image_data) / (1024 * 1024)
    if image_size_mb > settings.MAX_IMAGE_SIZE_MB:
        logger.warning(f"OCR image too large: {image_size_mb:.2f}MB")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Image size exceeds {settings.MAX_IMAGE_SIZE_MB}MB limit"
        )
    
    logger.info(f"Starting OCR analysis (size: {image_size_mb:.2f}MB)")
    
    try:
        # 3. Execute OCR pipeline
        result = await pipeline.execute(image_data)
        
        # 4. Log results
        processing_time = time.time() - start_time
        extracted_text = result.get("details", {}).get("extracted_text", "")
        
        logger.info(
            f"OCR analysis completed",
            extra={
                "risk_score": result["risk_score"],
                "category": result["category"],
                "processing_time_ms": round(processing_time * 1000, 2),
                "text_length": len(extracted_text),
                "scam_indicators": len(result.get("details", {}).get("scam_indicators", []))
            }
        )
        
        # 5. Return formatted response
        return AnalysisResponse(
            risk_score=result["risk_score"],
            category=result["category"],
            explanation=result["explanation"],
            details={
                **result.get("details", {}),
                "processing_time_ms": round(processing_time * 1000, 2),
                "extracted_text_preview": extracted_text[:200] + "..." if len(extracted_text) > 200 else extracted_text
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OCR analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze image: {str(e)}"
        )

@router.post("/ocr/upload", response_model=AnalysisResponse)
async def analyze_ocr_upload(
    file: UploadFile = File(...),
    pipeline: OCRPipeline = Depends(get_ocr_pipeline)
) -> AnalysisResponse:
    """
    OCR analysis via file upload
    
    Alternative endpoint accepting multipart/form-data.
    
    Args:
        file: Uploaded image file
        pipeline: OCR pipeline
    
    Returns:
        AnalysisResponse with scam detection results
    """
    try:
        import base64
        
        # Validate file type
        allowed_types = ["image/png", "image/jpeg", "image/jpg"]
        if file.content_type not in allowed_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported file type. Allowed: {', '.join(allowed_types)}"
            )
        
        # Read and encode
        contents = await file.read()
        image_base64 = base64.b64encode(contents).decode('utf-8')
        
        logger.info(f"OCR upload received: {file.filename} ({len(contents)} bytes)")
        
        request = OCRAnalysisRequest(image=image_base64)
        return await analyze_ocr(request, pipeline)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OCR upload failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process uploaded file: {str(e)}"
        )

@router.post("/ocr/text", response_model=AnalysisResponse)
async def analyze_text_directly(
    request: Dict[str, str]
) -> AnalysisResponse:
    """
    Analyze text directly without OCR
    
    Useful when text is already extracted (e.g., from clipboard).
    Skips the OCR step and goes straight to scam detection.
    
    Args:
        request: Dictionary with 'text' field
    
    Returns:
        AnalysisResponse with scam detection results
    
    TODO: Share logic with OCR pipeline's text analysis
    """
    from app.services.heuristic_engine import HeuristicEngine
    from app.services.risk_scoring import RiskScorer
    
    text = request.get("text", "").strip()
    
    if not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text is required"
        )
    
    if len(text) > 10000:  # Limit text length
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Text exceeds maximum length of 10,000 characters"
        )
    
    logger.info(f"Analyzing text directly (length: {len(text)})")
    
    try:
        # Run heuristic analysis
        heuristic_engine = HeuristicEngine()
        analysis = heuristic_engine.analyze_text(text)
        
        # Calculate risk score
        risk_scorer = RiskScorer()
        risk_result = risk_scorer.calculate_ocr_risk(text, analysis)
        
        # Generate explanation
        explanation = _generate_ocr_explanation(
            risk_result["score"],
            risk_result["category"],
            analysis
        )
        
        return AnalysisResponse(
            risk_score=risk_result["score"],
            category=risk_result["category"],
            explanation=explanation,
            details={
                "extracted_text": text[:500],
                "scam_indicators": analysis["indicators"],
                "confidence": risk_result["confidence"],
                "direct_text_analysis": True
            }
        )
        
    except Exception as e:
        logger.error(f"Direct text analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze text: {str(e)}"
        )

def _generate_ocr_explanation(
    risk_score: float,
    category: str,
    analysis: Dict[str, Any]
) -> str:
    """
    Generate user-friendly explanation for OCR results
    
    Args:
        risk_score: Calculated risk score
        category: Detected category
        analysis: Heuristic analysis results
    
    Returns:
        Human-readable explanation
    """
    if risk_score < 0.3:
        return "No scam indicators detected in this content."
    
    explanations = {
        "banking_scam": "This message contains suspicious banking requests. Legitimate banks never ask for your PIN or OTP via messages.",
        "investment_scam": "This appears to be an investment scam promising unrealistic returns. Be cautious of 'get rich quick' schemes.",
        "urgent_action": "This message creates false urgency to trick you into taking immediate action without thinking.",
        "account_verification": "This is likely a fake account verification request designed to steal your login credentials.",
        "prize_scam": "This appears to be a fake prize/lottery notification. You cannot win a prize you never entered."
    }
    
    base_explanation = explanations.get(
        category,
        "This content contains indicators of a potential scam. Be cautious before taking any action."
    )
    
    indicators = analysis.get("indicators", [])
    if indicators:
        indicator_list = ", ".join([f'"{ind}"' for ind in indicators[:3]])
        return f"{base_explanation} Detected indicators: {indicator_list}."
    
    return base_explanation