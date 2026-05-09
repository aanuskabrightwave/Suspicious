# AYUSH WORK AREA
# Constants utility for the AI Engine
# Implements CONTEXT.md: "Use constants instead of hardcoded values"
# Centralizes all magic numbers and configuration values

from typing import Dict, List, Tuple, Optional
from enum import Enum

class ScanType(str, Enum):
    """Supported scan types"""
    URL = "URL"
    QR = "QR"
    OCR = "OCR"
    APK = "APK"

class RiskLevel(str, Enum):
    """Standardized risk levels"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ThreatCategory(str, Enum):
    """Threat categories for classification"""
    PHISHING = "phishing"
    BANKING_SCAM = "banking_scam"
    INVESTMENT_SCAM = "investment_scam"
    PRIZE_SCAM = "prize_scam"
    VERIFICATION_SCAM = "verification_scam"
    URGENT_ACTION = "urgent_action"
    QR_PHISHING = "qr_phishing"
    MALWARE = "malware"
    SPYWARE = "spyware"
    SAFE = "safe"
    UNKNOWN = "unknown"

# API endpoints
API_ENDPOINTS = {
    "URL_SCAN": "/api/v1/scan/url",
    "QR_SCAN": "/api/v1/scan/qr",
    "OCR_SCAN": "/api/v1/scan/ocr",
    "APK_SCAN": "/api/v1/scan/apk",
    "HEALTH_CHECK": "/health",
    "BATCH_SCAN": "/api/v1/batch/analyze"
}

# Default configuration values
DEFAULT_CONFIG = {
    # Processing timeouts
    "MAX_PROCESSING_TIME_MS": 30000,  # 30 seconds
    "OCR_TIMEOUT_MS": 10000,          # 10 seconds for OCR
    "ML_TIMEOUT_MS": 20000,           # 20 seconds for ML models
    
    # Image processing
    "MAX_IMAGE_SIZE_MB": 10,          # Maximum image size
    "MAX_APK_SIZE_MB": 100,           # Maximum APK size
    "OCR_LANGUAGES": ["eng"],         # Default OCR languages
    
    # Caching
    "URL_CACHE_TTL": 86400,           # 24 hours in seconds
    "SCAN_CACHE_TTL": 3600,           # 1 hour in seconds
    
    # Heuristic thresholds
    "HEURISTIC_CONFIDENCE_THRESHOLD": 0.7,  # Minimum confidence for heuristic-only results
    "MIN_RISK_SCORE_FOR_ALERT": 0.6,        # Minimum risk score to trigger alerts
    
    # Model paths
    "PHISHING_MODEL_PATH": "./models/phishing_classifier_v1.pkl",
    "SCAM_MODEL_PATH": "./models/scam_classifier_v1.pkl",
    "RISK_MODEL_PATH": "./models/risk_classifier_v1.pkl",
    "FRAUD_MODEL_PATH": "./models/fraud_classifier_v1.pkl",
    
    # Redis configuration
    "REDIS_URL": "redis://localhost:6379/0",
    "REDIS_CACHE_DB": 0,
    "REDIS_QUEUE_DB": 1,
    
    # AI Engine URLs
    "AI_ENGINE_URL": "http://localhost:8001",
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
    '.date', '.stream', '.download', '.bid', '.loan', '.review',
    '.online', '.site', '.club', '.info', '.biz'
}

# High-risk permissions for APK analysis
HIGH_RISK_PERMISSIONS = {
    'android.permission.READ_SMS',
    'android.permission.SEND_SMS',
    'android.permission.RECEIVE_SMS',
    'android.permission.READ_CONTACTS',
    'android.permission.WRITE_CONTACTS',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.CAMERA',
    'android.permission.RECORD_AUDIO',
    'android.permission.READ_PHONE_STATE',
    'android.permission.CALL_PHONE',
    'android.permission.WRITE_EXTERNAL_STORAGE',
    'android.permission.REQUEST_INSTALL_PACKAGES',
    'android.permission.SYSTEM_ALERT_WINDOW'
}

# Common scam keywords by category
SCAM_KEYWORDS = {
    "banking": [
        "otp", "pin", "password", "cvv", "verify", "login", "account",
        "bank", "secure", "transaction", "balance"
    ],
    "investment": [
        "return", "profit", "earn", "investment", "crypto", "bitcoin",
        "guaranteed", "risk-free", "double", "ROI"
    ],
    "prize": [
        "won", "winner", "selected", "congratulations", "lucky",
        "prize", "lottery", "jackpot", "reward", "gift"
    ],
    "urgent": [
        "urgent", "immediate", "now", "today", "asap", "critical",
        "emergency", "warning", "alert", "suspended", "blocked"
    ]
}

# QR code payload types
QR_PAYLOAD_TYPES = {
    "URL": "url",
    "TEXT": "text",
    "CONTACT": "contact",
    "WIFI": "wifi",
    "EMAIL": "email",
    "BITCOIN": "bitcoin"
}

# Default response messages
DEFAULT_RESPONSE_MESSAGES = {
    "SUCCESS": "Operation completed successfully",
    "ERROR": "An error occurred during processing",
    "INVALID_INPUT": "Invalid input provided",
    "RATE_LIMIT_EXCEEDED": "Rate limit exceeded. Please try again later.",
    "SERVICE_UNAVAILABLE": "Service temporarily unavailable",
    "AUTH_REQUIRED": "Authentication required",
    "NOT_FOUND": "Resource not found"
}