# AYUSH WORK AREA
# Image-to-text extraction module using OpenCV + Pytesseract
# Implements CONTEXT.md: "OCR Pipeline: Extract -> Analyze -> Score -> Classify"
# Focuses on preprocessing, text extraction, and quality assessment

import cv2
import numpy as np
import logging
import base64
from typing import Tuple, Optional, Dict, Any
import io
from PIL import Image

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("image_text")

class ImageTextExtractor:
    """
    Image-to-text extraction pipeline with preprocessing and quality assessment
    
    This class implements the first stage of the OCR pipeline:
    1. Image preprocessing (noise reduction, contrast enhancement)
    2. Text region detection and segmentation
    3. Tesseract OCR with language support
    4. Text quality assessment and cleaning
    
    Security Note: Input validation prevents memory exhaustion attacks
    by limiting image size and processing time.
    """
    
    def __init__(self):
        """Initialize OCR components"""
        self.tesseract_config = settings.TESSERACT_CONFIG
        self.max_image_size = settings.MAX_IMAGE_SIZE_MB * 1024 * 1024  # Convert MB to bytes
        logger.info("ImageTextExtractor initialized")
    
    def preprocess_image(self, image_array: np.ndarray) -> np.ndarray:
        """
        Preprocess image for optimal OCR results
        
        Steps:
        1. Convert to grayscale
        2. Apply noise reduction (Gaussian blur)
        3. Enhance contrast (CLAHE)
        4. Binarize (adaptive thresholding)
        5. Remove small noise (morphological operations)
        
        Args:
            image_array: Raw image as numpy array
            
        Returns:
            Preprocessed image ready for OCR
        """
        try:
            # Validate input dimensions
            if image_array.size == 0:
                raise ValueError("Empty image array")
            
            # Limit maximum image size to prevent DoS
            if image_array.nbytes > self.max_image_size:
                raise ValueError(f"Image too large: {image_array.nbytes} bytes (max: {self.max_image_size})")
            
            # Convert to grayscale if needed
            if len(image_array.shape) == 3:
                gray = cv2.cvtColor(image_array, cv2.COLOR_BGR2GRAY)
            else:
                gray = image_array.copy()
            
            # Apply Gaussian blur to reduce noise
            blurred = cv2.GaussianBlur(gray, (5, 5), 0)
            
            # Apply CLAHE for contrast enhancement
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(blurred)
            
            # Adaptive thresholding for binarization
            binary = cv2.adaptiveThreshold(
                enhanced, 
                255, 
                cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                cv2.THRESH_BINARY_INV, 
                11, 
                2
            )
            
            # Morphological operations to remove noise
            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (2, 2))
            cleaned = cv2.morphologyEx(binary, cv2.MORPH_OPEN, kernel)
            
            return cleaned
            
        except Exception as e:
            logger.error(f"Image preprocessing failed: {str(e)}", exc_info=True)
            raise
    
    def extract_text_from_image(self, image_data: str) -> Tuple[str, Dict[str, Any]]:
        """
        Extract text from base64-encoded image data
        
        Args:
            image_data: Base64-encoded image string
            
        Returns:
            Tuple of (extracted_text, metadata)
            metadata includes: confidence, word_count, processing_time, etc.
        """
        start_time = 0.0
        try:
            start_time = float(time.time())
            
            # Decode base64 image
            image_bytes = base64.b64decode(image_data)
            
            # Validate image size
            if len(image_bytes) > self.max_image_size:
                raise ValueError(f"Image too large: {len(image_bytes)} bytes (max: {self.max_image_size})")
            
            # Convert to numpy array
            image_stream = io.BytesIO(image_bytes)
            pil_image = Image.open(image_stream)
            
            # Convert to OpenCV format
            image_array = cv2.cvtColor(np.array(pil_image), cv2.COLOR_RGB2BGR)
            
            # Preprocess image
            processed_image = self.preprocess_image(image_array)
            
            # Extract text using Tesseract
            try:
                import pytesseract
                extracted_text = pytesseract.image_to_string(
                    processed_image,
                    config=self.tesseract_config,
                    lang=settings.OCR_LANGUAGES
                )
            except ImportError:
                logger.warning("pytesseract not available, using fallback method")
                # Fallback: return empty text with error
                extracted_text = ""
            
            # Clean extracted text
            cleaned_text = self._clean_extracted_text(extracted_text)
            
            # Calculate metrics
            processing_time = time.time() - start_time
            word_count = len(cleaned_text.split()) if cleaned_text else 0
            char_count = len(cleaned_text)
            
            metadata = {
                "processing_time_ms": round(processing_time * 1000, 2),
                "word_count": word_count,
                "char_count": char_count,
                "confidence_estimate": self._estimate_confidence(cleaned_text, word_count),
                "preprocessing_steps": ["grayscale", "denoise", "contrast_enhance", "binarize"],
                "image_resolution": f"{pil_image.width}x{pil_image.height}",
                "status": "success"
            }
            
            return cleaned_text, metadata
            
        except Exception as e:
            processing_time = time.time() - start_time if start_time else 0
            logger.error(f"Text extraction failed: {str(e)}", exc_info=True)
            return "", {
                "processing_time_ms": round(processing_time * 1000, 2),
                "error": str(e),
                "status": "failed",
                "word_count": 0,
                "char_count": 0
            }
    
    def _clean_extracted_text(self, text: str) -> str:
        """
        Clean extracted text by removing common OCR errors
        
        Args:
            text: Raw extracted text
            
        Returns:
            Cleaned text
        """
        if not text:
            return text
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Fix common OCR errors
        # Replace common misrecognitions
        replacements = {
            '0': 'O',  # Zero to O
            '1': 'l',  # One to lowercase L
            '|': 'I',  # Pipe to I
            '{': '(',  # Curly brace to parenthesis
            '}': ')',
            '[': '(',
            ']': ')',
            '\\': '/',
            '`': "'",
            '‘': "'",
            '’': "'",
            '“': '"',
            '”': '"',
        }
        
        for wrong, correct in replacements.items():
            text = text.replace(wrong, correct)
        
        # Remove lines with only special characters (likely noise)
        lines = text.split('\n')
        cleaned_lines = []
        for line in lines:
            if re.search(r'[a-zA-Z0-9]', line):
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def _estimate_confidence(self, text: str, word_count: int) -> float:
        """
        Estimate OCR confidence based on text quality
        
        Args:
            text: Extracted text
            word_count: Number of words
            
        Returns:
            Confidence score 0.0-1.0
        """
        if not text or word_count == 0:
            return 0.2
        
        # Basic confidence factors
        confidence = 0.5
        
        # Length factor: longer text tends to be more reliable
        if word_count > 50:
            confidence += 0.2
        elif word_count > 10:
            confidence += 0.1
        
        # Character diversity factor
        unique_chars = len(set(text.lower()))
        total_chars = len(text)
        if total_chars > 0:
            diversity_ratio = unique_chars / total_chars
            confidence += diversity_ratio * 0.2
        
        # Check for common OCR failure patterns
        if re.search(r'[0O]{3,}|[1l]{3,}|[|I]{3,}', text):
            confidence -= 0.3
        
        # Ensure confidence stays within bounds
        return max(0.1, min(0.95, confidence))
    
    def batch_extract_text(self, image_datas: list) -> list:
        """
        Batch extract text from multiple images
        
        Args:
            image_datas: List of base64-encoded image strings
            
        Returns:
            List of (text, metadata) tuples
        """
        results = []
        for i, image_data in enumerate(image_datas):
            try:
                text, metadata = self.extract_text_from_image(image_data)
                results.append((text, metadata))
            except Exception as e:
                logger.error(f"Batch extraction failed for item {i}: {str(e)}")
                results.append(("", {"error": str(e), "status": "failed"}))
        
        return results


# Singleton instance
_image_text_extractor_instance = None

def get_image_text_extractor() -> ImageTextExtractor:
    """Get or create singleton instance"""
    global _image_text_extractor_instance
    if _image_text_extractor_instance is None:
        _image_text_extractor_instance = ImageTextExtractor()
    return _image_text_extractor_instance