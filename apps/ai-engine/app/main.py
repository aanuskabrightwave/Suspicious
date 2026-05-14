# AYUSH WORK AREA
# FastAPI application entry point for the AI detection engine
# Implements REST endpoints for the backend API (Shivam's domain) to interact with
# Follows modular pipeline architecture for different threat detection types

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from typing import Dict, Any

# Local imports
from config import settings
from schemas.common import AnalysisResponse
from pipelines.url_pipeline import URLPipeline
from pipelines.qr_pipeline import QRPipeline
from utils.logger import setup_logger
from utils.validators import validate_url, validate_base64_image

# Initialize logger
logger = setup_logger("ai_engine")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize resources when the application starts"""
    logger.info("Starting AI Engine initialization...")
    
    # Initialize pipeline components
    app.state.url_pipeline = URLPipeline()
    app.state.qr_pipeline = QRPipeline()
    
    logger.info("AI Engine initialized successfully")
    yield
    logger.info("AI Engine shutting down...")

app = FastAPI(
    title="SentinelAI Engine",
    description="AI-powered cybersecurity threat detection engine",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration - must match backend API origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root() -> Dict[str, Any]:
    """Root endpoint to verify service is running and provide entry points"""
    return {
        "message": "SentinelAI Engine is active and protecting your digital space",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "redoc": "/redoc"
        },
        "author": "Ayush"
    }

@app.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint for monitoring"""
    return {"status": "healthy", "service": "ai-engine"}

@app.post("/analyze/url", response_model=AnalysisResponse)
async def analyze_url(
    data: Dict[str, str],
    pipeline: URLPipeline = Depends(lambda: app.state.url_pipeline)
) -> AnalysisResponse:
    """
    Analyze a URL for phishing and scam risks
    
    This endpoint is called by Shivam's backend when a new URL scan is requested.
    Uses both heuristic checks and ML classification for comprehensive analysis.
    
    Args:
        data: Dictionary containing 'url' key with the URL to analyze
    
    Returns:
        AnalysisResponse with risk score and explanation
    
    Raises:
        HTTPException: If URL is invalid or analysis fails
    """
    url = data.get("url", "").strip()
    
    if not url:
        logger.warning("URL analysis request received with empty URL")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required"
        )
    
    try:
        # Validate URL format
        if not validate_url(url):
            logger.warning(f"Invalid URL format received: {url}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid URL format"
            )
        
        logger.info(f"Starting URL analysis for: {url}")
        result = await pipeline.execute(url)
        logger.info(f"URL analysis completed for {url} with risk score: {result['risk_score']}")
        
        return AnalysisResponse(
            risk_score=result["risk_score"],
            category=result["category"],
            explanation=result["explanation"],
            details=result.get("details", {})
        )
    except Exception as e:
        logger.error(f"URL analysis failed for {url}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze URL"
        )

@app.post("/analyze/qr", response_model=AnalysisResponse)
async def analyze_qr(
    data: Dict[str, str],
    pipeline: QRPipeline = Depends(lambda: app.state.qr_pipeline)
) -> AnalysisResponse:
    """
    Analyze a QR code or image for scam content
    
    This endpoint is called by Shivam's backend when a QR/image scan is requested.
    Uses OCR and NLP analysis to detect scam content in images.
    
    Args:
        data: Dictionary containing 'image' key with base64 encoded image
    
    Returns:
        AnalysisResponse with risk score and explanation
    
    Raises:
        HTTPException: If image data is invalid or analysis fails
    """
    image_data = data.get("image", "").strip()
    
    if not image_data:
        logger.warning("QR analysis request received with empty image data")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Image data is required"
        )
    
    try:
        # Validate base64 image format
        if not validate_base64_image(image_data):
            logger.warning("Invalid base64 image format received")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid image format"
            )
        
        logger.info("Starting QR/image analysis")
        result = await pipeline.execute(image_data)
        logger.info(f"QR analysis completed with risk score: {result['risk_score']}")
        
        return AnalysisResponse(
            risk_score=result["risk_score"],
            category=result["category"],
            explanation=result["explanation"],
            details=result.get("details", {})
        )
    except Exception as e:
        logger.error(f"QR analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to analyze QR code"
        )

@app.post("/analyze/apk", response_model=AnalysisResponse)
async def analyze_apk(
    data: Dict[str, Any]
) -> AnalysisResponse:
    """
    Analyze APK files for malicious behavior
    
    TODO: Implement full APK analysis pipeline
    - Requires integration with sandbox environment
    - Need to set up proper file storage and processing
    
    Args:
        data: Dictionary containing APK metadata and potentially file data
    
    Returns:
        AnalysisResponse with risk score and explanation
    
    Raises:
        HTTPException: If analysis fails
    """
    logger.warning("APK analysis endpoint called but not fully implemented")
    
    # TODO: Implement actual APK analysis
    # 1. Validate and store APK file
    # 2. Run in sandbox environment
    # 3. Analyze permissions, network calls, etc.
    # 4. Return comprehensive risk assessment
    
    return AnalysisResponse(
        risk_score=0.0,
        category="pending",
        explanation="APK analysis is currently being processed. Results will be available shortly.",
        details={"status": "processing"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app", 
        host=settings.HOST, 
        port=settings.PORT,
        reload=settings.DEBUG
    )