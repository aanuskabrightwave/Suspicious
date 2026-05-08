# AYUSH WORK AREA
# Text cleaning and normalization module
# Implements CONTEXT.md: "OCR Pipeline: Extract -> Analyze -> Score -> Classify"
# Focuses on post-processing extracted text for better analysis

import re
import logging
import unicodedata
from typing import Dict, List, Tuple, Optional
import string

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("text_cleaner")

class TextCleaner:
    """
    Text cleaning and normalization for OCR output
    
    This class implements the preprocessing step after text extraction
    but before scam detection. It handles:
    
    1. Normalization of Unicode characters
    2. Removal of OCR artifacts and noise
    3. Standardization of spacing and punctuation
    4. Language-specific cleaning rules
    
    The goal is to improve downstream analysis accuracy by providing
    clean, normalized text to the scam detector and risk classifier.
    """
    
    def __init__(self):
        """Initialize text cleaning rules"""
        self._initialize_cleaning_rules()
        logger.info("TextCleaner initialized")
    
    def _initialize_cleaning_rules(self):
        """Initialize cleaning rules and patterns"""
        # Common OCR errors mapping
        self.ocr_error_map = {
            # Zero vs O
            '0': 'O',
            'o': 'O',
            # One vs l vs I
            '1': 'l',
            '|': 'I',
            'l': 'I',
            # Quotes and apostrophes
            '‘': "'",
            '’': "'",
            '“': '"',
            '”': '"',
            # Brackets
            '{': '(',
            '}': ')',
            '[': '(',
            ']': ')',
            # Other common substitutions
            '\\': '/',
            '`': "'",
            '´': "'",
            '¨': '',
            'ˆ': '',
            '˜': '',
        }
        
        # Patterns to remove (noise)
        self.noise_patterns = [
            # Multiple consecutive spaces/dots
            (r'\.{3,}', '...'),
            (r'\s{2,}', ' '),  # Multiple spaces
            (r'-{2,}', '--'),  # Multiple hyphens
            (r'_{2,}', '__'),  # Multiple underscores
            # Random symbols that appear in OCR
            (r'[•◦▪▫‣⁃]', ''),  # Bullet points
            (r'[§©®™]', ''),   # Copyright symbols
        ]
        
        # Language-specific rules
        self.lang_rules = {
            'eng': {
                'abbreviations': {
                    'u': 'you',
                    'r': 'are',
                    'b': 'be',
                    'thru': 'through',
                    ' thru ': ' through ',
                    ' w/ ': ' with ',
                    ' w/o ': ' without '
                },
                'common_ocr_fixes': {
                    'rn': 'run',
                    'rn ': 'run ',
                    'cl': 'call',
                    'cl ': 'call ',
                    'plz': 'please',
                    'plz ': 'please '
                }
            },
            'hin': {
                # Hindi-specific cleaning
                'devanagari_normalization': True
            }
        }
    
    def clean_text(self, text: str, language: str = 'eng') -> Dict[str, Any]:
        """
        Clean and normalize extracted text
        
        Args:
            text: Raw text to clean
            language: Language code for language-specific rules
            
        Returns:
            Dictionary with:
                - cleaned_text: Cleaned text
                - original_length: Original text length
                - cleaned_length: Cleaned text length
                - changes_made: List of cleaning operations performed
                - confidence: Cleaning confidence (0.0-1.0)
        """
        if not text:
            return {
                "cleaned_text": "",
                "original_length": 0,
                "cleaned_length": 0,
                "changes_made": [],
                "confidence": 1.0
            }
        
        original_length = len(text)
        changes_made = []
        
        # Step 1: Normalize Unicode
        normalized = self._normalize_unicode(text)
        if normalized != text:
            changes_made.append("unicode_normalization")
        
        # Step 2: Apply OCR error fixes
        corrected = self._fix_ocr_errors(normalized)
        if corrected != normalized:
            changes_made.append("ocr_error_correction")
        
        # Step 3: Apply noise removal patterns
        cleaned = self._remove_noise(corrected)
        if cleaned != corrected:
            changes_made.append("noise_removal")
        
        # Step 4: Language-specific cleaning
        if language in self.lang_rules:
            lang_cleaned = self._apply_language_rules(cleaned, language)
            if lang_cleaned != cleaned:
                changes_made.append(f"language_specific_cleaning_{language}")
                cleaned = lang_cleaned
        
        # Step 5: Final normalization
        final_text = self._final_normalization(cleaned)
        if final_text != cleaned:
            changes_made.append("final_normalization")
        
        cleaned_length = len(final_text)
        
        # Calculate confidence
        confidence = self._calculate_cleaning_confidence(
            original_length, cleaned_length, changes_made
        )
        
        return {
            "cleaned_text": final_text,
            "original_length": original_length,
            "cleaned_length": cleaned_length,
            "changes_made": changes_made,
            "confidence": confidence
        }
    
    def _normalize_unicode(self, text: str) -> str:
        """
        Normalize Unicode characters to standard forms
        
        Args:
            text: Input text
            
        Returns:
            Normalized text
        """
        # Normalize to NFC form (composed characters)
        normalized = unicodedata.normalize('NFC', text)
        
        # Replace common Unicode lookalikes
        for char, replacement in self.ocr_error_map.items():
            normalized = normalized.replace(char, replacement)
        
        return normalized
    
    def _fix_ocr_errors(self, text: str) -> str:
        """
        Fix common OCR errors
        
        Args:
            text: Input text
            
        Returns:
            Text with OCR errors fixed
        """
        fixed = text
        
        # Apply OCR error map
        for wrong, correct in self.ocr_error_map.items():
            fixed = fixed.replace(wrong, correct)
        
        # Fix common character substitutions
        fixes = [
            ('rn', 'run'),
            ('cl', 'call'),
            ('plz', 'please'),
            ('thx', 'thanks'),
            ('btw', 'by the way'),
            ('im', 'I am'),
            ('ur', 'your'),
            ('u', 'you'),
            ('r', 'are'),
        ]
        
        for wrong, correct in fixes:
            fixed = re.sub(r'\b' + wrong + r'\b', correct, fixed, flags=re.IGNORECASE)
        
        return fixed
    
    def _remove_noise(self, text: str) -> str:
        """
        Remove noise patterns from text
        
        Args:
            text: Input text
            
        Returns:
            Text with noise removed
        """
        cleaned = text
        
        # Apply noise patterns
        for pattern, replacement in self.noise_patterns:
            cleaned = re.sub(pattern, replacement, cleaned)
        
        # Remove leading/trailing whitespace
        cleaned = cleaned.strip()
        
        # Remove empty lines
        lines = [line.strip() for line in cleaned.split('\n') if line.strip()]
        cleaned = '\n'.join(lines)
        
        return cleaned
    
    def _apply_language_rules(self, text: str, language: str) -> str:
        """
        Apply language-specific cleaning rules
        
        Args:
            text: Input text
            language: Language code
            
        Returns:
            Language-optimized text
        """
        if language not in self.lang_rules:
            return text
        
        rules = self.lang_rules[language]
        cleaned = text
        
        # Apply abbreviation expansions
        if 'abbreviations' in rules:
            for abbr, full in rules['abbreviations'].items():
                cleaned = re.sub(r'\b' + abbr + r'\b', full, cleaned, flags=re.IGNORECASE)
        
        # Apply common OCR fixes
        if 'common_ocr_fixes' in rules:
            for wrong, correct in rules['common_ocr_fixes'].items():
                cleaned = cleaned.replace(wrong, correct)
        
        return cleaned
    
    def _final_normalization(self, text: str) -> str:
        """
        Final text normalization
        
        Args:
            text: Input text
            
        Returns:
            Fully normalized text
        """
        # Ensure consistent spacing
        normalized = re.sub(r'\s+', ' ', text)
        
        # Fix common punctuation spacing
        normalized = re.sub(r'\s*([,\.!\?;:])\s*', r'\1 ', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        
        # Remove trailing punctuation
        normalized = re.sub(r'[,.!?;:]+$', '', normalized)
        
        return normalized
    
    def _calculate_cleaning_confidence(
        self, 
        original_length: int, 
        cleaned_length: int, 
        changes_made: List[str]
    ) -> float:
        """
        Calculate confidence in cleaning process
        
        Args:
            original_length: Original text length
            cleaned_length: Cleaned text length
            changes_made: List of cleaning operations
            
        Returns:
            Confidence score 0.0-1.0
        """
        if original_length == 0:
            return 1.0
        
        # Base confidence
        confidence = 0.7
        
        # Adjust for text reduction
        reduction_ratio = abs(original_length - cleaned_length) / original_length
        if reduction_ratio > 0.5:
            confidence -= 0.3  # Large reduction may indicate over-cleaning
        elif reduction_ratio > 0.2:
            confidence -= 0.1
        
        # Adjust for number of changes
        change_count = len(changes_made)
        if change_count > 5:
            confidence -= 0.2  # Many changes may indicate poor OCR quality
        
        # Ensure confidence stays within bounds
        return max(0.3, min(0.95, confidence))
    
    def clean_and_analyze(self, text: str, language: str = 'eng') -> Dict[str, Any]:
        """
        Clean text and provide analysis of cleaning effectiveness
        
        Args:
            text: Raw text to process
            language: Language code
            
        Returns:
            Comprehensive cleaning and analysis results
        """
        # Clean the text
        cleaning_result = self.clean_text(text, language)
        
        # Analyze the cleaned text
        analysis = self._analyze_cleaned_text(cleaning_result["cleaned_text"])
        
        return {
            **cleaning_result,
            "analysis": analysis,
            "processing_time_ms": 0.0  # Will be set by caller
        }
    
    def _analyze_cleaned_text(self, text: str) -> Dict[str, Any]:
        """
        Analyze cleaned text for quality metrics
        
        Args:
            text: Cleaned text
            
        Returns:
            Analysis metrics
        """
        if not text:
            return {
                "word_count": 0,
                "char_count": 0,
                "avg_word_length": 0,
                "readability_score": 0,
                "contains_numbers": False,
                "contains_urls": False,
                "contains_emails": False,
                "language_confidence": 0.5
            }
        
        words = text.split()
        word_count = len(words)
        char_count = len(text)
        avg_word_length = char_count / word_count if word_count > 0 else 0
        
        # Readability estimation (Flesch-Kincaid simplified)
        sentences = len(re.split(r'[.!?]+', text))
        syllables = sum(len(re.findall(r'[aeiouy]+', word.lower())) for word in words)
        readability = 0
        if sentences > 0 and word_count > 0:
            readability = 206.835 - 1.015 * (word_count / sentences) - 84.6 * (syllables / word_count)
            readability = max(0, min(100, readability)) / 100  # Normalize to 0-1
        
        # Detection metrics
        contains_numbers = bool(re.search(r'\d', text))
        contains_urls = bool(re.search(r'https?://', text))
        contains_emails = bool(re.search(r'\b[\w.-]+@[\w.-]+\.\w+\b', text))
        
        return {
            "word_count": word_count,
            "char_count": char_count,
            "avg_word_length": round(avg_word_length, 2),
            "readability_score": round(readability, 2),
            "contains_numbers": contains_numbers,
            "contains_urls": contains_urls,
            "contains_emails": contains_emails,
            "language_confidence": 0.8  # Placeholder
        }


# Singleton instance
_text_cleaner_instance = None

def get_text_cleaner() -> TextCleaner:
    """Get or create singleton instance"""
    global _text_cleaner_instance
    if _text_cleaner_instance is None:
        _text_cleaner_instance = TextCleaner()
    return _text_cleaner_instance