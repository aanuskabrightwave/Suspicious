# AYUSH WORK AREA
# QR code scanner module for scam detection
# Implements CONTEXT.md: "Scams: OCR-based detection of WhatsApp/SMS/QR scams"
# Focuses on QR code extraction, payload analysis, and scam detection

import logging
import base64
import cv2
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
import re
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings
from app.ocr.image_text import get_image_text_extractor
from app.heuristics.domain_checks import get_domain_checker
from app.heuristics.keyword_checks import get_keyword_checker
from app.heuristics.redirect_checks import get_redirect_checker

logger = setup_logger("qr_scanner")

class QRScanner:
    """
    QR code scanning and analysis module
    
    This class implements the complete QR scanning pipeline:
    1. QR code detection and decoding
    2. Payload analysis (URL, text, contact, etc.)
    3. URL safety analysis (if payload is a URL)
    4. Scam detection in QR payload
    5. Risk scoring and explanation generation
    
    Security Note: QR codes are a common vector for phishing attacks.
    This scanner provides comprehensive analysis to detect malicious QR content.
    """
    
    def __init__(self):
        """Initialize QR scanning components"""
        self.image_text_extractor = get_image_text_extractor()
        self.domain_checker = get_domain_checker()
        self.keyword_checker = get_keyword_checker()
        self.redirect_checker = get_redirect_checker()
        logger.info("QRScanner initialized")
    
    def scan_qr(self, image_data: str) -> Dict[str, Any]:
        """
        Scan QR code from image data
        
        Args:
            image_data: Base64-encoded image containing QR code
            
        Returns:
            Dictionary with scan results including:
                - risk_score: Overall risk score (0.0-1.0)
                - category: Detected threat category
                - explanation: User-friendly explanation
                - details: Technical details
        """
        start_time = datetime.utcnow()
        
        try:
            # Decode image data
            image_bytes = base64.b64decode(image_data)
            
            # Validate image size
            if len(image_bytes) > settings.MAX_IMAGE_SIZE_MB * 1024 * 1024:
                raise ValueError(f"Image too large: {len(image_bytes)} bytes")
            
            # Extract QR code payload
            qr_payload, qr_metadata = self._decode_qr_code(image_bytes)
            
            if not qr_payload:
                return {
                    "risk_score": 0.0,
                    "category": "no_qr",
                    "explanation": "No QR code detected in the image.",
                    "details": {
                        "analysis_time": (datetime.utcnow() - start_time).total_seconds(),
                        "qr_metadata": qr_metadata
                    }
                }
            
            # Analyze QR payload
            payload_analysis = self._analyze_qr_payload(qr_payload)
            
            # Calculate risk score
            risk_score = self._calculate_qr_risk(payload_analysis)
            
            # Determine category
            category = self._determine_qr_category(risk_score, payload_analysis)
            
            # Generate explanation
            explanation = self._generate_qr_explanation(risk_score, category, payload_analysis)
            
            return {
                "risk_score": risk_score,
                "category": category,
                "explanation": explanation,
                "details": {
                    "qr_payload": qr_payload,
                    "payload_analysis": payload_analysis,
                    "analysis_time": (datetime.utcnow() - start_time).total_seconds(),
                    "qr_metadata": qr_metadata
                }
            }
            
        except Exception as e:
            logger.error(f"QR scanning failed: {str(e)}", exc_info=True)
            return {
                "risk_score": 0.5,
                "category": "error",
                "explanation": "Failed to analyze QR code. Please try again with a clearer image.",
                "details": {
                    "error": str(e),
                    "analysis_time": (datetime.utcnow() - start_time).total_seconds()
                }
            }
    
    def _decode_qr_code(self, image_bytes: bytes) -> Tuple[str, Dict[str, Any]]:
        """
        Decode QR code from image
        
        Args:
            image_bytes: Raw image data
            
        Returns:
            Tuple of (payload, metadata)
        """
        try:
            # Convert to OpenCV format
            image_array = np.frombuffer(image_bytes, dtype=np.uint8)
            image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
            
            if image is None:
                raise ValueError("Failed to decode image")
            
            # Convert to grayscale
            if len(image.shape) == 3:
                gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            else:
                gray = image
            
            # Use OpenCV QR code detector
            qr_detector = cv2.QRCodeDetector()
            data, bbox, _ = qr_detector.detectAndDecode(gray)
            
            # If OpenCV fails, try alternative method
            if not data:
                # Fallback: use pyzbar if available
                try:
                    import pyzbar.pyzbar as pyzbar
                    decoded_objects = pyzbar.decode(image)
                    if decoded_objects:
                        data = decoded_objects[0].data.decode('utf-8')
                except ImportError:
                    pass
            
            # Prepare metadata
            metadata = {
                "detected": bool(data),
                "bbox": bbox.tolist() if bbox is not None else None,
                "image_width": image.shape[1] if len(image.shape) > 1 else 0,
                "image_height": image.shape[0] if len(image.shape) > 1 else 0,
                "confidence": 0.8 if data else 0.0
            }
            
            return data or "", metadata
            
        except Exception as e:
            logger.error(f"QR decoding failed: {str(e)}")
            return "", {"error": str(e), "detected": False}
    
    def _analyze_qr_payload(self, payload: str) -> Dict[str, Any]:
        """
        Analyze QR code payload for security threats
        
        Args:
            payload: Decoded QR code content
            
        Returns:
            Dictionary with payload analysis results
        """
        analysis = {
            "payload": payload,
            "payload_type": self._detect_payload_type(payload),
            "url_analysis": None,
            "text_analysis": None,
            "keyword_analysis": None,
            "domain_analysis": None,
            "redirect_analysis": None
        }
        
        try:
            # Analyze based on payload type
            if analysis["payload_type"] == "url":
                # URL analysis
                url_analysis = self._analyze_url_payload(payload)
                analysis["url_analysis"] = url_analysis
                
                # Domain analysis
                domain_analysis = self.domain_checker.analyze_domain(payload)
                analysis["domain_analysis"] = domain_analysis
                
                # Redirect analysis
                redirect_analysis = self.redirect_checker.analyze_redirect_chain(payload, follow_redirects=False)
                analysis["redirect_analysis"] = redirect_analysis
                
            elif analysis["payload_type"] in ["text", "contact", "wifi", "email"]:
                # Text analysis
                text_analysis = self._analyze_text_payload(payload)
                analysis["text_analysis"] = text_analysis
                
                # Keyword analysis
                keyword_analysis = self.keyword_checker.analyze_text(payload)
                analysis["keyword_analysis"] = keyword_analysis
            
            # Common analysis
            analysis["length"] = len(payload)
            analysis["contains_special_chars"] = bool(re.search(r'[^\w\s]', payload))
            analysis["contains_digits"] = bool(re.search(r'\d', payload))
            
        except Exception as e:
            logger.error(f"Payload analysis failed: {str(e)}")
            analysis["error"] = str(e)
        
        return analysis
    
    def _detect_payload_type(self, payload: str) -> str:
        """
        Detect QR payload type
        
        Args:
            payload: Decoded QR content
            
        Returns:
            Payload type string
        """
        if not payload:
            return "empty"
        
        # URL detection
        if payload.startswith(('http://', 'https://')):
            return "url"
        
        # Email detection
        if '@' in payload and '.' in payload.split('@')[-1]:
            return "email"
        
        # Phone number detection
        if payload.startswith('tel:') or re.match(r'^\+?\d{10,}$', payload.replace('-', '').replace(' ', '')):
            return "phone"
        
        # WiFi network detection
        if payload.startswith('WIFI:'):
            return "wifi"
        
        # Contact/vCard detection
        if payload.startswith('BEGIN:VCARD'):
            return "contact"
        
        # Bitcoin address detection
        if payload.startswith(('bitcoin:', 'bc1', '1', '3')) and len(payload) >= 26:
            return "bitcoin"
        
        # Generic text
        return "text"
    
    def _analyze_url_payload(self, url: str) -> Dict[str, Any]:
        """
        Analyze URL payload for security threats"""
        

        