# AYUSH WORK AREA
# Main router that aggregates all scanning endpoints
# Provides unified API interface for Shivam's backend to interact with
# Follows FastAPI best practices for modular route organization

from fastapi import APIRouter, HTTPException, status
from typing import Dict, Any, List
import logging

# Import individual scan routers
from .url_scan import router as url_router
from .qr_scan import router as qr_router
from .ocr_scan import router as ocr_router
from .apk_scan import router as apk_router

# Local imports
from app.schemas.common import AnalysisResponse, HealthCheckResponse
from app.utils.logger import setup_logger

logger = setup_logger("scanner_router")

# Create main router with prefix for API versioning
router = APIRouter(
    prefix="/api/v1",
    tags=["Scanner API"],
    responses={
        404: {"description": "Endpoint not found"},
        500: {"description": "Internal server error"}
    }
)

# Include all scan-type specific routers
router.include_router(url_router, prefix="/scan", tags=["URL Scanning"])
router.include_router(qr_router, prefix="/scan", tags=["QR Scanning"])
router.include_router(ocr_router, prefix="/scan", tags=["OCR Scanning"])
router.include_router(apk_router, prefix="/scan", tags=["APK Scanning"])

@router.get("/health", response_model=HealthCheckResponse)
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint for monitoring and load balancers
    
    Returns:
        Health status with service metadata
    
    This endpoint is called by:
    - Kubernetes liveness/readiness probes
    - Shivam's backend health monitoring
    - Infrastructure monitoring tools
    """
    return {
        "status": "healthy",
        "service": "sentinel-ai-engine",
        "version": "1.0.0",
        "endpoints_available": [
            "/api/v1/scan/url",
            "/api/v1/scan/qr",
            "/api/v1/scan/ocr",
            "/api/v1/scan/apk"
        ]
    }

@router.get("/capabilities", response_model=Dict[str, Any])
async def get_capabilities() -> Dict[str, Any]:
    """
    Returns the scanning capabilities and supported formats
    
    This helps Shivam's backend understand what analysis types
    are available without hardcoding them.
    """
    return {
        "url_scanning": {
            "enabled": True,
            "methods": ["phishing_detection", "domain_analysis", "ssl_verification"],
            "max_url_length": 2048
        },
        "qr_scanning": {
            "enabled": True,
            "formats": ["QR_CODE", "DATA_MATRIX", "AZTEC"],
            "max_image_size_mb": 10
        },
        "ocr_scanning": {
            "enabled": True,
            "languages": ["eng", "hin"],  # English and Hindi
            "max_image_size_mb": 10
        },
        "apk_scanning": {
            "enabled": True,
            "max_apk_size_mb": 100,
            "analysis_types": ["permissions", "signatures", "behavioral"]
        }
    }

@router.post("/batch/analyze", response_model=List[AnalysisResponse])
async def batch_analyze(
    scans: List[Dict[str, Any]]
) -> List[AnalysisResponse]:
    """
    Batch analysis endpoint for multiple scans
    
    Allows Shivam's backend to submit multiple scan requests
    in a single API call for efficiency.
    
    Args:
        scans: List of scan requests with 'type' and 'data' fields
    
    Returns:
        List of analysis responses
    
    TODO: Implement parallel processing for batch requests
    TODO: Add rate limiting per batch size
    """
    logger.info(f"Batch analysis request received with {len(scans)} items")
    
    results = []
    for scan in scans:
        scan_type = scan.get("type", "").upper()
        data = scan.get("data", "")
        
        try:
            # Route to appropriate scanner based on type
            if scan_type == "URL":
                # Import here to avoid circular dependencies
                from .url_scan import analyze_url
                result = await analyze_url({"url": data})
            elif scan_type == "QR":
                from .qr_scan import analyze_qr
                result = await analyze_qr({"image": data})
            elif scan_type == "OCR":
                from .ocr_scan import analyze_ocr
                result = await analyze_ocr({"image": data})
            elif scan_type == "APK":
                from .apk_scan import analyze_apk
                result = await analyze_apk({"apk_data": data})
            else:
                result = AnalysisResponse(
                    risk_score=0.0,
                    category="error",
                    explanation=f"Unsupported scan type: {scan_type}",
                    details={"error": "invalid_type"}
                )
            
            results.append(result)
        except Exception as e:
            logger.error(f"Batch scan failed for type {scan_type}: {str(e)}")
            results.append(AnalysisResponse(
                risk_score=0.0,
                category="error",
                explanation="Scan processing failed",
                details={"error": str(e)}
            ))
    
    return results

# Error handlers for the router
@router.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Custom error handler for HTTP exceptions"""
    logger.error(f"HTTP Exception: {exc.detail}", exc_info=True)
    return {
        "status": "error",
        "status_code": exc.status_code,
        "detail": exc.detail
    }