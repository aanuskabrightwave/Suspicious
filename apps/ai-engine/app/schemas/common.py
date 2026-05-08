# AYUSH WORK AREA
# APK-specific analysis schemas for malware detection
# Implements CONTEXT.md: "App Safety: Malicious APK and overlay attack detection"
# Handles static analysis of Android APK files

from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
import base64
import hashlib

from .common import AnalysisResponse, ScanMetadata

class APKAnalysisRequest(BaseModel):
    """
    Request schema for APK analysis operations
    
    Handles APK file data for malware and permission analysis.
    Includes validation to prevent malicious file uploads.
    
    Security Note: APK files can be large and complex. Validation
    includes size limits and format checks to prevent DoS attacks.
    """
    apk_data: str = Field(
        ..., 
        description="Base64-encoded APK file data for analysis"
    )
    package_name: Optional[str] = Field(
        None, 
        description="Expected package name for verification"
    )
    app_name: Optional[str] = Field(
        None, 
        description="Expected app name for verification"
    )
    
    @validator('apk_data')
    def validate_apk_data(cls, v):
        """Validate base64 APK data"""
        if not v:
            raise ValueError('APK data cannot be empty')
        
        # Validate base64 encoding
        try:
            decoded = base64.b64decode(v)
        except Exception:
            raise ValueError('Invalid base64 encoding')
        
        # Validate APK size (prevent DoS - reasonable limit)
        if len(decoded) > 100 * 1024 * 1024:  # 100MB limit
            raise ValueError('APK exceeds maximum size of 100MB')
        
        # Basic APK format check (starts with PK signature)
        if len(decoded) < 4 or decoded[:4] != b'PK\x03\x04':
            raise ValueError('File does not appear to be a valid APK')
        
        return v

class APKAnalysisResponse(AnalysisResponse):
    """
    Enhanced response for APK analysis operations
    
    Extends common AnalysisResponse with APK-specific fields
    to provide detailed information about app security assessment.
    """
    package_name: Optional[str] = Field(
        None, 
        description="Package name of the APK"
    )
    app_name: Optional[str] = Field(
        None, 
        description="Display name of the app"
    )
    version_name: Optional[str] = Field(
        None, 
        description="Version name of the app"
    )
    version_code: Optional[int] = Field(
        None, 
        description="Version code of the app"
    )
    permissions: Optional[List[str]] = Field(
        None, 
        description="List of permissions requested by the app"
    )
    high_risk_permissions: Optional[List[str]] = Field(
        None, 
        description="List of high-risk permissions detected"
    )
    certificate_info: Optional[Dict[str, Any]] = Field(
        None, 
        description="Certificate information for the APK"
    )
    manifest_analysis: Optional[Dict[str, Any]] = Field(
        None, 
        description="Analysis of AndroidManifest.xml"
    )
    file_analysis: Optional[Dict[str, Any]] = Field(
        None, 
        description="Analysis of APK file structure and contents"
    )
    
    class Config:
        # Allow additional fields for extensibility
        extra = "allow"

class APKScanMetadata(ScanMetadata):
    """
    APK-specific scan metadata
    
    Contains additional metadata relevant to APK analysis operations.
    """
    package_name: Optional[str] = Field(None, description="APK package name")
    version_name: Optional[str] = Field(None, description="APK version name")
    version_code: Optional[int] = Field(None, description="APK version code")
    file_size: Optional[int] = Field(None, description="APK file size in bytes")
    file_hash: Optional[str] = Field(None, description="SHA-256 hash of APK file")
    total_files: Optional[int] = Field(None, description="Total number of files in APK")
    total_permissions: Optional[int] = Field(None, description="Total number of permissions requested")
    high_risk_permission_count: Optional[int] = Field(None, description="Count of high-risk permissions")

class PermissionAnalysis(BaseModel):
    """
    Analysis of individual permission requests
    
    Provides detailed information about each permission and its risk level.
    """
    permission: str = Field(..., description="Android permission name")
    description: Optional[str] = Field(None, description="Description of the permission")
    risk_level: str = Field(..., description="Risk level (low, medium, high)")
    reason: Optional[str] = Field(None, description="Reason for risk level assignment")
    recommended_action: Optional[str] = Field(None, description="Recommended action for user")

class CertificateInfo(BaseModel):
    """
    Information about APK certificate
    
    Contains details about the signing certificate used to verify APK authenticity.
    """
    issuer: Optional[str] = Field(None, description="Certificate issuer")
    subject: Optional[str] = Field(None, description="Certificate subject")
    valid_from: Optional[str] = Field(None, description="Certificate validity start date")
    valid_until: Optional[str] = Field(None, description="Certificate validity end date")
    fingerprint: Optional[str] = Field(None, description="Certificate fingerprint")
    is_valid: Optional[bool] = Field(None, description="Whether certificate is valid")
    is_trusted: Optional[bool] = Field(None, description="Whether certificate is from trusted authority")

class APKThreatIndicator(BaseModel):
    """
    Individual threat indicator within APK analysis
    
    Represents specific elements of an APK that contributed to the risk assessment.
    """
    type: str = Field(..., description="Type of threat (e.g., permission, file, code)")
    description: str = Field(..., description="Description of the threat indicator")
    severity: str = Field(..., description="Severity level (low, medium, high)")
    score_contribution: float = Field(..., ge=0.0, le=1.0, description="Contribution to overall risk score")
    evidence: Optional[str] = Field(None, description="Evidence supporting this indicator")
    file_path: Optional[str] = Field(None, description="File path where threat was found")