# AYUSH WORK AREA
# Centralized logging utility for the AI Engine
# Implements CONTEXT.md: "Enterprise-grade logging with structured JSON output"
# Follows security best practices for log sanitization

import logging
import json
import os
import sys
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

class StructuredJSONFormatter(logging.Formatter):
    """
    Custom JSON formatter for structured logging
    
    This formatter converts log records to JSON format with:
    - Timestamp in ISO format
    - Log level
    - Module name
    - Function name
    - Line number
    - Message
    - Additional contextual data
    
    Security Note: Sanitizes sensitive fields like tokens and credentials from logs.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Fields to sanitize (never log these values)
        self.sensitive_fields = {
            'token', 'password', 'secret', 'api_key', 'access_token',
            'refresh_token', 'credentials', 'session', 'cookie'
        }
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        # Create base log dictionary
        log_dict = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'module': record.name,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
            'process_id': os.getpid(),
            'thread_id': record.thread
        }
        
        # Add extra context if available
        if hasattr(record, 'extra'):
            log_dict['context'] = self._sanitize_dict(record.extra)
        
        # Add exception info if present
        if record.exc_info:
            log_dict['exception'] = self._format_exception(record.exc_info)
        
        # Sanitize sensitive data
        log_dict = self._sanitize_dict(log_dict)
        
        # Convert to JSON
        try:
            return json.dumps(log_dict, default=self._json_default_serializer)
        except Exception as e:
            # Fallback to string representation if JSON fails
            return f"JSON_LOG_ERROR: {str(e)} | {log_dict}"
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize sensitive fields in a dictionary
        
        Args:
            data: Dictionary to sanitize
            
        Returns:
            Sanitized dictionary
        """
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            # Check if key contains sensitive pattern
            if any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, str) and any(
                sensitive in value.lower() for sensitive in self.sensitive_fields
            ):
                sanitized[key] = "[REDACTED]"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _format_exception(self, exc_info: tuple) -> Dict[str, str]:
        """
        Format exception information for JSON logging
        
        Args:
            exc_info: Exception info tuple
            
        Returns:
            Formatted exception dictionary
        """
        import traceback
        exc_type, exc_value, exc_traceback = exc_info
        
        return {
            'type': exc_type.__name__,
            'message': str(exc_value),
            'traceback': ''.join(traceback.format_exception(exc_type, exc_value, exc_traceback)).strip()
        }
    
    def _json_default_serializer(self, obj: Any) -> str:
        """
        Default serializer for non-serializable objects
        
        Args:
            obj: Object to serialize
            
        Returns:
            String representation
        """
        if isinstance(obj, (datetime,)):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return str(obj)
        else:
            return repr(obj)


def setup_logger(name: str, level: str = None) -> logging.Logger:
    """
    Setup structured logger for AI Engine components
    
    Args:
        name: Logger name (typically module name)
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger instance
    """
    # Get log level from environment or use default
    if level is None:
        level = os.getenv('LOG_LEVEL', 'INFO').upper()
    
    # Create logger
    logger = logging.getLogger(name)
    
    # Avoid adding handlers multiple times
    if not logger.handlers:
        # Set level
        logger.setLevel(getattr(logging, level))
        
        # Create console handler
        console_handler = logging.StreamHandler(sys.stdout)
        
        # Create formatter
        formatter = StructuredJSONFormatter()
        
        # Set formatter
        console_handler.setFormatter(formatter)
        
        # Add handler
        logger.addHandler(console_handler)
        
        # Add file handler for production
        if os.getenv('ENVIRONMENT') == 'production':
            log_dir = Path('logs')
            log_dir.mkdir(exist_ok=True)
            file_handler = logging.FileHandler(log_dir / f'{name}.log')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
    
    return logger


# Global logger instances for common modules
def get_ai_engine_logger() -> logging.Logger:
    """Get logger for AI Engine core components"""
    return setup_logger("ai_engine")

def get_scanner_logger() -> logging.Logger:
    """Get logger for scanner modules"""
    return setup_logger("scanner")

def get_ocr_logger() -> logging.Logger:
    """Get logger for OCR modules"""
    return setup_logger("ocr")

def get_classifier_logger() -> logging.Logger:
    """Get logger for classifier modules"""
    return setup_logger("classifier")


# Convenience functions for common logging patterns
def log_info(logger: logging.Logger, message: str, **context: Any) -> None:
    """Log info message with context"""
    logger.info(message, extra=context)

def log_warning(logger: logging.Logger, message: str, **context: Any) -> None:
    """Log warning message with context"""
    logger.warning(message, extra=context)

def log_error(logger: logging.Logger, message: str, **context: Any) -> None:
    """Log error message with context"""
    logger.error(message, extra=context)

def log_debug(logger: logging.Logger, message: str, **context: Any) -> None:
    """Log debug message with context"""
    logger.debug(message, extra=context)

def log_critical(logger: logging.Logger, message: str, **context: Any) -> None:
    """Log critical message with context"""
    logger.critical(message, extra=context)


# Initialize global logger
logger = get_ai_engine_logger()

# Log startup
logger.info("AI Engine logger initialized", extra={
    "version": "1.0.0",
    "environment": os.getenv('ENVIRONMENT', 'development'),
    "pid": os.getpid()
})