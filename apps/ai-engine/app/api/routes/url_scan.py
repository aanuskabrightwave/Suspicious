# AYUSH WORK AREA
# URL phishing and scam detection endpoint
# Implements CONTEXT.md flow: Check Cache -> AI Analysis -> Return Risk Score
# Integrates heuristic engine and ML classifier for comprehensive analysis

from fastapi import APIRouter, HTTPException, status, Depends
from typing import Dict, Any, Optional
import logging
import time

# Local imports
from app.schemas.url import URLAnalysisRequest, URLAnalysisResponse
from app.schemas.common import AnalysisResponse
from app.pipelines.url_pipeline import URLPipeline
from app.utils.validators import validate_url, sanitize_url
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("url_scan")

# Create router for URL-specific endpoints
router = APIRouter()

# Initialize URL pipeline (singleton pattern)
def get_url_pipeline() -> URLPipeline:
    """Dependency injection for URL pipeline"""
    return URLPipeline()

@router.post("/url", response_model=AnalysisResponse)
async def analyze_url(
    request: URLAnalysisRequest,
    pipeline: URLPipeline = Depends(get_url_pipeline)
) -> AnalysisResponse:
    """
    Analyze a URL for phishing, scams, and security threats
    
    This is the primary endpoint called by Shivam's backend when a user
    submits a URL for scanning via the mobile app.
    
    Flow:
    1. Validate and sanitize URL input
    2. Check Redis cache for recent analysis (if enabled)
    3. Run heuristic checks (fast, rule-based)
    4. Run ML classifier (if confidence < threshold)
    5. Calculate risk score and generate explanation
    6. Cache result and return to backend
    
    Args:
        request: URLAnalysisRequest with the URL to analyze
        pipeline: Injected URL analysis pipeline
    
    Returns:
        AnalysisResponse with risk_score, category, and explanation
    
    Raises:
        HTTPException: If URL is invalid or analysis fails
    
    Security Note: URL is sanitized before processing to prevent
    injection attacks in downstream components.
    """
    start_time = time.time()
    url = request.url.strip()
    
    # 1. Input validation
    if not url:
        logger.warning("URL analysis request received with empty URL")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL is required"
        )
    
    # 2. URL validation and sanitization
    if not validate_url(url):
        logger.warning(f"Invalid URL format received: {url[:100]}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL format. Please provide a valid HTTP/HTTPS URL"
        )
    
    sanitized_url = sanitize_url(url)
    logger.info(f"Starting URL analysis for: {sanitized_url[:100]}...")
    
    try:
        # 3. Check cache (if Redis is configured)
        if settings.USE_REDIS_CACHE:
            from app.services.cache_service import CacheService
            cached_result = await CacheService.get_url_analysis(sanitized_url)
            if cached_result:
                logger.info(f"Cache hit for URL: {sanitized_url[:50]}...")
                cached_result["details"]["cached"] = True
                return AnalysisResponse(**cached_result)
        
        # 4. Execute full analysis pipeline
        result = await pipeline.execute(sanitized_url)
        
        # 5. Cache the result (TTL: 24 hours per CONTEXT.md)
        if settings.USE_REDIS_CACHE:
            from app.services.cache_service import CacheService
            await CacheService.set_url_analysis(
                sanitized_url,
                result,
                ttl=settings.URL_CACHE_TTL
            )
        
        # 6. Calculate processing time for monitoring
        processing_time = time.time() - start_time
        logger.info(
            f"URL analysis completed",
            extra={
                "url": sanitized_url[:50],
                "risk_score": result["risk_score"],
                "category": result["category"],
                "processing_time_ms": round(processing_time * 1000, 2),
                "cached": False
            }
        )
        
        # 7. Return formatted response
        return AnalysisResponse(
            risk_score=result["risk_score"],
            category=result["category"],
            explanation=result["explanation"],
            details={
                **result.get("details", {}),
                "processing_time_ms": round(processing_time * 1000, 2),
                "cached": False
            }
        )
        
    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(
            f"URL analysis failed: {str(e)}",
            extra={"url": sanitized_url[:100]},
            exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to analyze URL: {str(e)}"
        )

@router.get("/url/bulk", response_model=List[AnalysisResponse])
async def bulk_analyze_urls(
    urls: str,  # Comma-separated URLs
    pipeline: URLPipeline = Depends(get_url_pipeline)
) -> List[AnalysisResponse]:
    """
    Analyze multiple URLs in a single request
    
    Useful for batch processing or when users share multiple links.
    
    Args:
        urls: Comma-separated list of URLs (max 10)
        pipeline: Injected URL pipeline
    
    Returns:
        List of analysis responses
    
    TODO: Implement parallel processing with asyncio.gather
    TODO: Add rate limiting for bulk requests
    """
    url_list = [u.strip() for u in urls.split(",") if u.strip()]
    
    if len(url_list) > 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 10 URLs allowed per bulk request"
        )
    
    results = []
    for url in url_list:
        try:
            result = await analyze_url(URLAnalysisRequest(url=url), pipeline)
            results.append(result)
        except Exception as e:
            logger.error(f"Bulk scan failed for URL {url}: {str(e)}")
            results.append(AnalysisResponse(
                risk_score=0.0,
                category="error",
                explanation="Scan failed",
                details={"error": str(e)}
            ))
    
    return results

@router.post("/url/quick-check", response_model=Dict[str, Any])
async def quick_url_check(
    request: URLAnalysisRequest
) -> Dict[str, Any]:
    """
    Lightweight URL check using only heuristic rules
    
    This endpoint skips ML classification for faster response times.
    Useful for real-time validation as users type URLs.
    
    Args:
        request: URL to check
    
    Returns:
        Quick analysis with heuristic-only results
    """
    from app.services.heuristic_engine import HeuristicEngine
    
    url = request.url.strip()
    
    if not validate_url(url):
        return {
            "risk_score": 0.0,
            "category": "invalid",
            "explanation": "Invalid URL format",
            "quick_check": True
        }
    
    # Run only heuristic checks (no ML)
    heuristic_engine = HeuristicEngine()
    analysis = heuristic_engine.analyze_url(url)
    
    risk_score = min(len(analysis["indicators"]) * 0.2, 0.8)
    
    return {
        "risk_score": risk_score,
        "category": analysis.get("primary_category", "safe"),
        "explanation": f"Quick check found {len(analysis['indicators'])} indicators",
        "indicators": analysis["indicators"],
        "quick_check": True
    }