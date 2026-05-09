# AYUSH WORK AREA
# Common schemas for AI detection engine
# Implements base models for all analysis responses

from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

class ScanMetadata(BaseModel):
    """
    Metadata for a scan operation
    """
    timestamp: str = Field(..., description="ISO timestamp of the scan")
    engine_version: str = Field(..., description="Version of the AI engine used")
    processing_time: float = Field(..., description="Time taken to process in seconds")

class AnalysisResponse(BaseModel):
    """
    Standard response format for all analysis endpoints
    """
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Normalized risk score from 0.0 to 1.0")
    category: str = Field(..., description="Primary threat category detected")
    explanation: str = Field(..., description="Human-readable explanation of the risk assessment")
    details: Dict[str, Any] = Field(default_factory=dict, description="Detailed analysis results from individual components")
    metadata: Optional[ScanMetadata] = Field(None, description="Metadata about the scan process")

# APK Specific (Moved here or kept for compatibility)
class APKAnalysisResponse(AnalysisResponse):
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    permissions: List[str] = []