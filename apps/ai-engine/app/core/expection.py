# AYUSH WORK AREA
# Core exception classes for the AI Engine
# Implements CONTEXT.md: "Use express-async-handler" equivalent for Python

from typing import Optional

class AIEngineError(Exception):
    """Base exception for AI Engine errors"""
    def __init__(self, message: str, code: str = "INTERNAL_ERROR", details: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

class ValidationError(AIEngineError):
    """Validation error for input validation"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, "VALIDATION_ERROR", details)

class ProcessingError(AIEngineError):
    """Error during processing (ML, OCR, etc.)"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, "PROCESSING_ERROR", details)

class ServiceUnavailableError(AIEngineError):
    """Service unavailable (Redis, external APIs, etc.)"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, "SERVICE_UNAVAILABLE", details)

class RateLimitError(AIEngineError):
    """Rate limit exceeded"""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, "RATE_LIMIT_EXCEEDED", details)

def handle_ai_exception(error: Exception) -> AIEngineError:
    """Convert generic exceptions to AIEngineError"""
    if isinstance(error, AIEngineError):
        return error
    elif isinstance(error, ValueError):
        return ValidationError(str(error))
    elif isinstance(error, TimeoutError):
        return ProcessingError(f"Operation timed out: {str(error)}")
    else:
        return AIEngineError(f"Unexpected error: {str(error)}", "INTERNAL_ERROR")