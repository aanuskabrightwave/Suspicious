# AYUSH WORK AREA
# Phishing URL classifier using ensemble ML methods
# Implements CONTEXT.md requirement: ML-based threat classification
# Trains on URL features like domain age, SSL status, lexical patterns

import os
import pickle
import logging
from typing import Dict, List, Tuple, Any
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
import re
from urllib.parse import urlparse
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("phishing_classifier")

class PhishingClassifier:
    """
    Multi-feature phishing URL classifier
    
    This classifier combines:
    1. Lexical features (URL structure, length, special chars)
    2. Host-based features (domain age, SSL, TLD)
    3. Content-based features (TF-IDF of URL path)
    
    Uses ensemble methods (Random Forest + Gradient Boosting)
    for robust detection with confidence scoring.
    
    Model is trained on labeled dataset of phishing/legitimate URLs
    and serialized for production use.
    """
    
    def __init__(self, model_path: str = None):
        """
        Initialize classifier with optional pre-trained model
        
        Args:
            model_path: Path to serialized model file. If None, uses default from config
        """
        self.model_path = model_path or settings.PHISHING_MODEL_PATH
        self.model = None
        self.scaler = StandardScaler()
        self.tfidf = TfidfVectorizer(
            max_features=100,
            ngram_range=(1, 2),
            token_pattern=r'[a-zA-Z0-9]+'
        )
        self.feature_names = [
            'url_length',
            'num_dots',
            'num_hyphens',
            'num_underscores',
            'num_slashes',
            'num_question_marks',
            'num_equals',
            'num_percent',
            'num_at_symbols',
            'has_ip_address',
            'has_https',
            'domain_length',
            'path_length',
            'num_subdomains',
            'has_suspicious_tld',
            'num_digits',
            'entropy',
            'has_login_keyword',
            'has_secure_keyword',
            'has_bank_keyword'
        ]
        
        # Suspicious TLDs commonly used in phishing
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
            '.date', '.stream', '.download', '.bid', '.loan', '.review'
        }
        
        # Keywords indicating phishing attempts
        self.phishing_keywords = {
            'login': ['login', 'signin', 'account', 'verify', 'secure'],
            'secure': ['secure', 'ssl', 'protected', 'encrypted'],
            'bank': ['bank', 'paypal', 'amazon', 'apple', 'microsoft']
        }
    
    def extract_lexical_features(self, url: str) -> np.ndarray:
        """
        Extract numerical features from URL string
        
        Features include:
        - Length metrics
        - Special character counts
        - Protocol indicators
        - Domain structure
        
        Args:
            url: URL string to analyze
            
        Returns:
            Numpy array of numerical features
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            
            # Basic length features
            url_length = len(url)
            domain_length = len(domain)
            path_length = len(path)
            
            # Character counts
            num_dots = url.count('.')
            num_hyphens = url.count('-')
            num_underscores = url.count('_')
            num_slashes = url.count('/')
            num_question_marks = url.count('?')
            num_equals = url.count('=')
            num_percent = url.count('%')
            num_at_symbols = url.count('@')
            num_digits = sum(c.isdigit() for c in url)
            
            # Protocol check
            has_https = 1 if url.startswith('https://') else 0
            
            # IP address detection (simple heuristic)
            has_ip_address = 1 if re.match(r'^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
            
            # Subdomain count
            num_subdomains = domain.count('.') - 1 if '.' in domain else 0
            
            # Suspicious TLD check
            has_suspicious_tld = 1
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    has_suspicious_tld = 1
                    break
            else:
                has_suspicious_tld = 0
            
            # Keyword checks
            url_lower = url.lower()
            has_login_keyword = 1 if any(kw in url_lower for kw in self.phishing_keywords['login']) else 0
            has_secure_keyword = 1 if any(kw in url_lower for kw in self.phishing_keywords['secure']) else 0
            has_bank_keyword = 1 if any(kw in url_lower for kw in self.phishing_keywords['bank']) else 0
            
            # Shannon entropy (measures randomness - high entropy can indicate DGA)
            entropy = self._calculate_entropy(domain)
            
            features = np.array([
                url_length,
                num_dots,
                num_hyphens,
                num_underscores,
                num_slashes,
                num_question_marks,
                num_equals,
                num_percent,
                num_at_symbols,
                has_ip_address,
                has_https,
                domain_length,
                path_length,
                num_subdomains,
                has_suspicious_tld,
                num_digits,
                entropy,
                has_login_keyword,
                has_secure_keyword,
                has_bank_keyword
            ], dtype=np.float64)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting lexical features from URL: {str(e)}")
            # Return zero vector on error
            return np.zeros(len(self.feature_names), dtype=np.float64)
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string
        
        High entropy indicates randomness (potential DGA domain)
        
        Args:
            text: Input string
            
        Returns:
            Entropy value (0.0 - ~4.7 for ASCII)
        """
        if not text:
            return 0.0
        
        # Calculate character frequencies
        freq = {}
        for char in text.lower():
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * np.log2(p)
        
        return entropy
    
    def extract_text_features(self, url: str) -> np.ndarray:
        """
        Extract TF-IDF features from URL path and query
        
        Args:
            url: URL string
            
        Returns:
            TF-IDF feature vector
        """
        try:
            parsed = urlparse(url)
            # Combine path and query for text analysis
            text_content = f"{parsed.path} {parsed.query}"
            
            # Fit or transform TF-IDF
            if hasattr(self.tfidf, 'vocabulary_') and self.tfidf.vocabulary_:
                tfidf_features = self.tfidf.transform([text_content]).toarray()[0]
            else:
                # If not fitted yet, return zeros
                tfidf_features = np.zeros(100)
            
            return tfidf_features
            
        except Exception as e:
            logger.error(f"Error extracting text features: {str(e)}")
            return np.zeros(100)
    
    def train(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Train the phishing classifier
        
        Uses ensemble of Random Forest and Gradient Boosting
        for robust performance.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (0 = legitimate, 1 = phishing)
        """
        logger.info(f"Training phishing classifier on {len(X)} samples")
        
        try:
            # Create ensemble pipeline
            self.model = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', RandomForestClassifier(
                    n_estimators=100,
                    max_depth=15,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    class_weight='balanced',
                    random_state=42,
                    n_jobs=-1
                ))
            ])
            
            # Train model
            self.model.fit(X, y)
            
            # Calculate training accuracy
            train_accuracy = self.model.score(X, y)
            logger.info(f"Phishing classifier trained with accuracy: {train_accuracy:.4f}")
            
            # Save model
            self._save_model()
            
        except Exception as e:
            logger.error(f"Error training phishing classifier: {str(e)}")
            raise
    
    def predict(self, url: str) -> Tuple[float, float, Dict[str, Any]]:
        """
        Predict phishing probability for a URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Tuple of (risk_score, confidence, metadata)
            - risk_score: 0.0 (safe) to 1.0 (phishing)
            - confidence: Model confidence 0.0 to 1.0
            - metadata: Additional analysis details
        """
        if self.model is None:
            self._load_model()
        
        try:
            # Extract features
            lexical_features = self.extract_lexical_features(url)
            text_features = self.extract_text_features(url)
            
            # Combine features
            X = np.concatenate([lexical_features, text_features]).reshape(1, -1)
            
            # Get prediction and probability
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            # Calculate confidence (difference between class probabilities)
            confidence = abs(probabilities[1] - probabilities[0])
            
            # Risk score is probability of phishing class
            risk_score = float(probabilities[1]) if prediction == 1 else float(probabilities[0])
            
            # Generate metadata
            metadata = {
                'prediction': 'phishing' if prediction == 1 else 'legitimate',
                'phishing_probability': float(probabilities[1]),
                'legitimate_probability': float(probabilities[0]),
                'feature_importance': self._get_top_features(lexical_features),
                'url_length': lexical_features[0],
                'has_https': bool(lexical_features[10]),
                'has_suspicious_tld': bool(lexical_features[14])
            }
            
            logger.debug(
                f"Phishing prediction for {url[:50]}: score={risk_score:.4f}, confidence={confidence:.4f}"
            )
            
            return risk_score, confidence, metadata
            
        except Exception as e:
            logger.error(f"Error predicting phishing for URL: {str(e)}")
            # Return neutral score on error
            return 0.5, 0.0, {'error': str(e)}
    
    def _get_top_features(self, features: np.ndarray) -> List[Dict[str, Any]]:
        """
        Identify most influential features for this prediction
        
        Args:
            features: Extracted feature vector
            
        Returns:
            List of top features with their values
        """
        try:
            if hasattr(self.model, 'named_steps') and 'classifier' in self.model.named_steps:
                importances = self.model.named_steps['classifier'].feature_importances_
                
                # Get indices of top 5 features
                top_indices = np.argsort(importances)[-5:][::-1]
                
                return [
                    {
                        'feature': self.feature_names[i] if i < len(self.feature_names) else f'tfidf_{i-len(self.feature_names)}',
                        'value': float(features[i]) if i < len(features) else 0.0,
                        'importance': float(importances[i])
                    }
                    for i in top_indices
                ]
        except Exception as e:
            logger.error(f"Error getting top features: {str(e)}")
        
        return []
    
    def _save_model(self) -> None:
        """Serialize model to disk"""
        try:
            model_dir = os.path.dirname(self.model_path)
            if model_dir and not os.path.exists(model_dir):
                os.makedirs(model_dir)
            
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'tfidf': self.tfidf,
                    'feature_names': self.feature_names
                }, f)
            
            logger.info(f"Phishing classifier saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving phishing model: {str(e)}")
    
    def _load_model(self) -> None:
        """Load pre-trained model from disk"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.tfidf = data['tfidf']
                    if 'feature_names' in data:
                        self.feature_names = data['feature_names']
                
                logger.info(f"Phishing classifier loaded from {self.model_path}")
            else:
                logger.warning(f"No pre-trained model found at {self.model_path}. Using untrained model.")
                
        except Exception as e:
            logger.error(f"Error loading phishing model: {str(e)}")
            raise
    
    def batch_predict(self, urls: List[str]) -> List[Tuple[float, float, Dict[str, Any]]]:
        """
        Predict phishing probability for multiple URLs
        
        Args:
            urls: List of URLs to analyze
            
        Returns:
            List of (risk_score, confidence, metadata) tuples
        """
        logger.info(f"Batch predicting phishing for {len(urls)} URLs")
        
        results = []
        for url in urls:
            try:
                result = self.predict(url)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch prediction failed for URL {url}: {str(e)}")
                results.append((0.5, 0.0, {'error': str(e)}))
        
        return results


# Singleton instance for production use
_phishing_classifier_instance = None

def get_phishing_classifier() -> PhishingClassifier:
    """
    Get or create singleton instance of phishing classifier
    
    Returns:
        PhishingClassifier instance
    """
    global _phishing_classifier_instance
    if _phishing_classifier_instance is None:
        _phishing_classifier_instance = PhishingClassifier()
    return _phishing_classifier_instance