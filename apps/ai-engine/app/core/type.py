# AYUSH WORK AREA
# Core type definitions for the AI Engine
# Implements CONTEXT.md: "Use interfaces from shared-types" but for Python
# Centralizes type hints for internal modules

from typing import Dict, Any, Optional, Union, List, Tuple
from datetime import datetime
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

# Core analysis result type
AnalysisResult = Dict[str, Union[float, str, Dict[str, Any], List[Any], datetime]]

# Scan request type
ScanRequest = Dict[str, Union[str, Dict[str, Any]]]

# Model prediction type
ModelPrediction = Tuple[float, float, Dict[str, Any]]  # (score, confidence, metadata)

# Pipeline stage type
PipelineStage = str

# Common response format
ApiResponse = Dict[str, Union[bool, str, Dict[str, Any], List[Any]]]