# AYUSH WORK AREA
# Core configuration management using Pydantic BaseSettings
# Centralizes all environment variables with proper validation
# Follows 12-factor app principles for configuration

from pydantic_settings import BaseSettings
from pydantic import Field, AnyHttpUrl
from typing import List, Optional
import os

class Settings(BaseSettings):
    """
    Application settings with validation
    
    All settings are loaded from environment variables with sensible defaults
    for development, but production requires explicit configuration.
    
    Security Note: Never store secrets in code - always use environment variables
    """
    
    # Application settings
    DEBUG: bool = Field(default=False, description="Enable debug mode")
    HOST: str = Field(default="0.0.0.0", description="Host to bind the application")
    PORT: int = Field(default=8001, description="Port to run the application")
    
    # Security settings
    SECRET_KEY: str = Field(
        default="change_this_in_production", 
        description="Secret key for cryptographic operations"
    )
    ALLOWED_ORIGINS: List[AnyHttpUrl] = Field(
        default_factory=lambda: ["http://localhost:3000"],
        description="CORS allowed origins"
    )
    
    # AI Model settings
    PHISHING_MODEL_PATH: str = Field(
        default="./models/phishing_classifier_v1.pkl",
        description="Path to the phishing classification model"
    )
    SCAM_MODEL_PATH: str = Field(
        default="./models/scam_classifier_v1.pkl",
        description="Path to the scam classification model"
    )
    RISK_MODEL_PATH: str = Field(
        default="./models/risk_classifier_v1.pkl",
        description="Path to the unified risk classification model"
    )
    FRAUD_MODEL_PATH: str = Field(
        default="./models/fraud_classifier_v1.pkl",
        description="Path to the fraud detection model"
    )
    MIN_CONFIDENCE_THRESHOLD: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold for model predictions"
    )
    
    # OCR settings
    TESSERACT_TIMEOUT: int = Field(
        default=10,
        description="Maximum time (seconds) to allow for OCR processing"
    )
    TESSERACT_CONFIG: str = Field(
        default="--oem 3 --psm 6",
        description="Tesseract configuration parameters"
    )
    
    # Redis connection for caching
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    CACHE_TTL: int = Field(
        default=86400,  # 24 hours
        description="Time-to-live for cached scan results (seconds)"
    )
    
    # External service integrations
    VIRUSTOTAL_API_KEY: Optional[str] = Field(
        default=None,
        description="VirusTotal API key"
    )
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"  # Allow extra environment variables

# Initialize settings
settings = Settings()

# Security validation
if not settings.SECRET_KEY or settings.SECRET_KEY == "change_this_in_production":
    if os.getenv("ENVIRONMENT") != "development":
        raise ValueError("SECRET_KEY must be set to a secure value in production")

# Log important configuration (without sensitive data)
if settings.DEBUG:
    import json
    from pydantic.json import pydantic_encoder
    safe_settings = {
        k: v for k, v in settings.dict().items() 
        if k not in ["SECRET_KEY", "VIRUSTOTAL_API_KEY"]
    }
    print(f"AI Engine Configuration: {json.dumps(safe_settings, indent=2, default=pydantic_encoder)}")