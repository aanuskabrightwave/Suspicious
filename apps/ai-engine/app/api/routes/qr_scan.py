# AYUSH WORK AREA
# QR code analysis endpoint for scam detection
# Extracts QR payload and analyzes for phishing/scam content
# Integrates with OCR pipeline for comprehensive image analysis

from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File
from typing import Dict, Any, Optional
import logging
import base64
import time

# Local imports
from app.schemas.qr import QRAnalysisRequest, QRAnalysisResponse
from app.schemas.common import AnalysisResponse
from app.pipelines.qr_pipeline import QRPipeline
from app.utils.validators import validate_base64_image, decode_base64_image
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("qr_scan")

# Create router for QR-specific endpoints
router = APIRouter()

# Initialize QR pipeline
def get_qr_pipeline() -> QRPipeline:
    """Dependency injection for QR pipeline"""
    return QRPipeline()

@router.post("/qr", response_model=AnalysisResponse)
async def analyze_qr(
    request: QRAnalysisRequest,
    pipeline: QRPipeline = Depends(get_qr_pipeline)
) -> AnalysisResponse:
    """
    Analyze a QR code image for scam content
    
    This endpoint processes QR codes submitted by users through
    Anuska's mobile app. It extracts the QR payload and analyzes
    it for malicious content.
    
    Flow:
    1. Validate and decode base64 image
    2. Preprocess image (OpenCV cleanup)
    3. Extract QR code payload
    4. Analyze extracted content (URL/text) for scams
    5. Return risk assessment
    
    Args:
        request: QRAnalysisRequest with base64 image data
        pipeline: Injected QR analysis pipeline
    
    Returns:
        AnalysisResponse with risk assessment
    
    Raises:
        HTTPException: If image is invalid or QR extraction fails
    
    Security Note: Image size is validated to prevent DoS attacks.
    Maximum allowed size is defined in settings.MAX_IMAGE_SIZE_MB.
    """
    start_time = time.time()
    image_data = request.image.strip()
    
    # 1. Validate input
    if not image_data:
        logger.warning("QR analysis request received with empty image data")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Image data is required"
        )
    
    # 2. Validate base64 format and size
    if not validate_base64_image(image_data):
        logger.warning("Invalid base64 image format received")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid image format. Expected base64-encoded PNG/JPEG"
        )
    
    # Check image size (prevent DoS)
    image_size_mb = len(image_data) / (1024 * 1024)
    if image_size_mb > settings.MAX_IMAGE_SIZE_MB:
        logger.warning(
            f"Image too large: {image_size_mb:.2f}MB (max: {settings.MAX_IMAGE_SIZE_MB}MB)"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Image size exceeds {settings.MAX_IMAGE_SIZE_MB}MB limit"
        )
    
    logger.info(f"Starting QR code analysis (size: {image_size_mb:.2f}MB)")
    
    try:
        # 3. Execute QR analysis pipeline
        result = await pipeline.execute(image_data)
        
        # 4. Log results
        processing_time = time.time() - start_time
        logger.info(
            f"QR analysis completed",
            extra={
                "risk_score": result["risk_score"],
                "category": result["category"],
                "processing_time_ms": round(processing_time * 1000, 2),
                "qr_payload_preview": result.get("details", {}).get("qr_payload", "")[:50]
            }
        )
        
        # 5. Return formatted response
        return AnalysisResponse(
            risk_score=result["risk_score"],
            category=result["category"],
            explanation=result["explanation"],
            details={
                **result.get("details", {}),
                "processing_time_ms": round(processing_time * 1000, 2)
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"QR analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze QR code: {str(e)}"
        )

@router.post("/qr/upload", response_model=AnalysisResponse)
async def analyze_qr_upload(
    file: UploadFile = File(...),
    pipeline: QRPipeline = Depends(get_qr_pipeline)
) -> AnalysisResponse:
    """
    Alternative endpoint for QR analysis via file upload
    
    This endpoint accepts multipart/form-data uploads instead of
    base64 JSON payloads. Useful for web interfaces or direct uploads.
    
    Args:
        file: Uploaded image file (PNG/JPEG)
        pipeline: Injected QR pipeline
    
    Returns:
        AnalysisResponse with risk assessment
    
    TODO: Add file type validation (magic bytes check)
    TODO: Implement virus scanning for uploaded files
    """
    start_time = time.time()
    
    # Validate file type
    allowed_types = ["image/png", "image/jpeg", "image/jpg"]
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file type. Allowed: {', '.join(allowed_types)}"
        )
    
    # Read and encode file
    try:
        contents = await file.read()
        image_base64 = base64.b64encode(contents).decode('utf-8')
        
        logger.info(f"QR upload received: {file.filename} ({len(contents)} bytes)")
        
        # Reuse the main analyze_qr logic
        request = QRAnalysisRequest(image=image_base64)
        return await analyze_qr(request, pipeline)
        
    except Exception as e:
        logger.error(f"QR upload processing failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process uploaded file: {str(e)}"
        )

@router.post("/qr/decode-only", response_model=Dict[str, Any])
async def decode_qr_only(
    request: QRAnalysisRequest,
    pipeline: QRPipeline = Depends(get_qr_pipeline)
) -> Dict[str, Any]:
    """
    Decode QR code without security analysis
    
    Returns the raw QR payload for debugging or custom processing.
    Useful when you want to handle the extracted content differently.
    
    Args:
        request: QR image data
        pipeline: QR pipeline
    
    Returns:
        Dictionary with decoded QR payload and metadata
    """
    try:
        # Use pipeline's decode method without full analysis
        qr_payload = await pipeline.decode_qr(request.image)
        
        return {
            "success": True,
            "qr_payload": qr_payload,
            "payload_type": _detect_payload_type(qr_payload),
            "message": "QR code decoded successfully"
        }
    except Exception as e:
        logger.error(f"QR decode failed: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "message": "Failed to decode QR code"
        }

def _detect_payload_type(payload: str) -> str:
    """
    Detect the type of QR payload (URL, text, contact, etc.)
    
    Args:
        payload: Decoded QR content
    
    Returns:
        Payload type classification
    """
    if not payload:
        return "unknown"
    
    payload_lower = payload.lower()
    
    if payload_lower.startswith(("http://", "https://")):
        return "url"
    elif payload_lower.startswith("mailto:"):
        return "email"
    elif payload_lower.startswith("tel:"):
        return "phone"
    elif payload_lower.startswith("wifi:"):
        return "wifi"
    elif payload_lower.startswith("begin:vcard"):
        return "contact"
    elif len(payload) < 100 and not any(c.isalpha() for c in payload):
        return "numeric"
    else:
        return "text"