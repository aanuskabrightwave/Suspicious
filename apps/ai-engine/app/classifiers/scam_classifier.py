# AYUSH WORK AREA
# Text-based scam classifier for OCR/WhatsApp/SMS analysis
# Detects investment scams, banking fraud, fake alerts
# Uses NLP techniques and pattern matching

import os
import pickle
import logging
from typing import Dict, List, Tuple, Any, Set
import numpy as np
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder
import re
from collections import Counter

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("scam_classifier")

class ScamClassifier:
    """
    Multi-class scam text classifier
    
    Detects various scam types from extracted text:
    - Banking scams (OTP/PIN requests)
    - Investment scams (fake returns)
    - Prize/lottery scams
    - Account verification scams
    - Urgent action scams
    
    Uses TF-IDF + SVM for text classification
    with keyword-based fallback for robustness.
    """
    
    def __init__(self, model_path: str = None):
        """
        Initialize scam classifier
        
        Args:
            model_path: Path to serialized model
        """
        self.model_path = model_path or settings.SCAM_MODEL_PATH
        self.model = None
        self.label_encoder = LabelEncoder()
        
        # Define scam categories
        self.categories = [
            'banking_scam',
            'investment_scam',
            'prize_scam',
            'verification_scam',
            'urgent_action',
            'qr_phishing',
            'safe'
        ]
        
        # Initialize TF-IDF vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=500,
            ngram_range=(1, 3),
            min_df=2,
            max_df=0.8,
            sublinear_tf=True
        )
        
        # Scam keyword databases
        self.scam_keywords = {
            'banking_scam': {
                'urgent': ['urgent', 'immediate', 'suspended', 'blocked', 'frozen'],
                'banking': ['bank', 'account', 'ifsc', 'micr', 'routing'],
                'credentials': ['otp', 'pin', 'password', 'cvv', 'otp', 'verify'],
                'action': ['click', 'verify', 'update', 'confirm', 'login']
            },
            'investment_scam': {
                'returns': ['return', 'profit', 'earn', 'income', 'passive'],
                'guarantees': ['guaranteed', 'risk-free', '100%', 'double'],
                'crypto': ['bitcoin', 'crypto', 'blockchain', 'mining', 'btc'],
                'urgency': ['limited', 'now', 'today', 'exclusive', 'offer']
            },
            'prize_scam': {
                'won': ['won', 'winner', 'selected', 'congratulations', 'lucky'],
                'prize': ['prize', 'lottery', 'jackpot', 'reward', 'gift'],
                'claim': ['claim', 'redeem', 'collect', 'receive'],
                'personal': ['personal', 'details', 'information', 'contact']
            },
            'verification_scam': {
                'verify': ['verify', 'verification', 'confirm', 'validate'],
                'account': ['account', 'profile', 'identity', 'kyc'],
                'suspended': ['suspended', 'deactivated', 'locked', 'disabled'],
                'action': ['click', 'link', 'button', 'here']
            },
            'urgent_action': {
                'urgency': ['urgent', 'immediate', 'emergency', 'critical', 'alert'],
                'threat': ['threat', 'virus', 'hacked', 'compromised', 'breach'],
                'deadline': ['now', 'today', '24 hours', 'immediately'],
                'consequence': ['lose', 'penalty', 'fine', 'legal', 'action']
            },
            'qr_phishing': {
                'qr': ['qr', 'code', 'scan', 'barcode'],
                'action': ['scan', 'use', 'pay', 'login', 'verify'],
                'purpose': ['payment', 'login', 'verification', 'access']
            }
        }
    
    def extract_text_features(self, text: str) -> Dict[str, Any]:
        """
        Extract linguistic and statistical features from text
        
        Args:
            text: Input text to analyze
            
        Returns:
            Dictionary of extracted features
        """
        features = {
            'length': len(text),
            'word_count': len(text.split()),
            'uppercase_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
            'digit_count': sum(1 for c in text if c.isdigit()),
            'special_char_count': sum(1 for c in text if not c.isalnum() and not c.isspace()),
            'exclamation_count': text.count('!'),
            'question_count': text.count('?'),
            'url_count': len(re.findall(r'https?://\S+', text)),
            'phone_count': len(re.findall(r'\b\d{10,}\b', text)),
            'email_count': len(re.findall(r'\b[\w.-]+@[\w.-]+\.\w+\b', text)),
            'avg_word_length': np.mean([len(word) for word in text.split()]) if text.split() else 0,
            'unique_word_ratio': len(set(text.lower().split())) / max(len(text.split()), 1)
        }
        
        return features
    
    def keyword_match_score(self, text: str, category: str) -> float:
        """
        Calculate keyword matching score for a category
        
        Args:
            text: Input text
            category: Scam category to check
            
        Returns:
            Score from 0.0 (no match) to 1.0 (strong match)
        """
        if category not in self.scam_keywords:
            return 0.0
        
        text_lower = text.lower()
        keywords = self.scam_keywords[category]
        
        total_matches = 0
        total_keywords = 0
        
        for subcategory, words in keywords.items():
            for word in words:
                total_keywords += 1
                if word in text_lower:
                    total_matches += 1
        
        return total_matches / max(total_keywords, 1)
    
    def detect_scam_indicators(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect specific scam indicators in text
        
        Args:
            text: Input text
            
        Returns:
            List of detected indicators with details
        """
        indicators = []
        text_lower = text.lower()
        
        # Check for banking indicators
        if any(word in text_lower for word in ['otp', 'pin', 'password', 'cvv']):
            indicators.append({
                'type': 'credential_request',
                'severity': 'high',
                'description': 'Requests sensitive banking credentials'
            })
        
        # Check for urgency
        if any(word in text_lower for word in ['urgent', 'immediate', 'now', 'today']):
            indicators.append({
                'type': 'urgency_tactic',
                'severity': 'medium',
                'description': 'Uses urgency to pressure action'
            })
        
        # Check for threats
        if any(word in text_lower for word in ['suspended', 'blocked', 'frozen', 'terminated']):
            indicators.append({
                'type': 'threat_language',
                'severity': 'high',
                'description': 'Threatens account suspension or closure'
            })
        
        # Check for unrealistic promises
        if any(word in text_lower for word in ['guaranteed', '100%', 'risk-free', 'double']):
            indicators.append({
                'type': 'unrealistic_promise',
                'severity': 'high',
                'description': 'Makes unrealistic financial promises'
            })
        
        # Check for prize/lottery
        if any(word in text_lower for word in ['won', 'winner', 'lottery', 'prize', 'selected']):
            indicators.append({
                'type': 'fake_prize',
                'severity': 'high',
                'description': 'Claims you won a prize/lottery'
            })
        
        # Check for QR codes
        if 'qr' in text_lower and any(word in text_lower for word in ['scan', 'code']):
            indicators.append({
                'type': 'qr_code_request',
                'severity': 'medium',
                'description': 'Requests QR code scanning'
            })
        
        # Check for URLs
        urls = re.findall(r'https?://\S+', text)
        if urls:
            indicators.append({
                'type': 'contains_url',
                'severity': 'low',
                'description': f'Contains {len(urls)} URL(s)',
                'urls': urls
            })
        
        return indicators
    
    def train(self, texts: List[str], labels: List[str]) -> None:
        """
        Train the scam classifier
        
        Args:
            texts: List of text samples
            labels: List of corresponding labels
        """
        logger.info(f"Training scam classifier on {len(texts)} samples")
        
        try:
            # Encode labels
            y_encoded = self.label_encoder.fit_transform(labels)
            
            # Create pipeline
            self.model = Pipeline([
                ('tfidf', self.vectorizer),
                ('classifier', SVC(
                    kernel='rbf',
                    C=10.0,
                    gamma='scale',
                    probability=True,
                    class_weight='balanced',
                    random_state=42
                ))
            ])
            
            # Train
            self.model.fit(texts, y_encoded)
            
            # Calculate accuracy
            accuracy = self.model.score(texts, y_encoded)
            logger.info(f"Scam classifier trained with accuracy: {accuracy:.4f}")
            
            # Save model
            self._save_model()
            
        except Exception as e:
            logger.error(f"Error training scam classifier: {str(e)}")
            raise
    
    def predict(self, text: str) -> Tuple[str, float, Dict[str, Any]]:
        """
        Predict scam category and risk score
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (category, risk_score, metadata)
        """
        if self.model is None:
            self._load_model()
        
        try:
            # Extract features
            text_features = self.extract_text_features(text)
            
            # Get ML prediction if model is trained
            if self.model:
                # Vectorize text
                X = self.vectorizer.transform([text])
                
                # Get prediction and probabilities
                pred_encoded = self.model.predict(X)[0]
                probabilities = self.model.predict_proba(X)[0]
                
                # Decode label
                category = self.label_encoder.inverse_transform([pred_encoded])[0]
                
                # Get confidence
                confidence = float(max(probabilities))
                
            else:
                # Fallback to keyword-based classification
                category, confidence = self._keyword_based_classify(text)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(category, confidence, text_features)
            
            # Detect specific indicators
            indicators = self.detect_scam_indicators(text)
            
            # Generate explanation
            explanation = self._generate_explanation(category, risk_score, indicators)
            
            metadata = {
                'category': category,
                'confidence': confidence,
                'indicators': indicators,
                'text_features': text_features,
                'explanation': explanation,
                'keyword_scores': {
                    cat: self.keyword_match_score(text, cat)
                    for cat in self.scam_keywords.keys()
                }
            }
            
            logger.debug(
                f"Scam classification: category={category}, risk={risk_score:.4f}, confidence={confidence:.4f}"
            )
            
            return category, risk_score, metadata
            
        except Exception as e:
            logger.error(f"Error predicting scam: {str(e)}")
            return 'unknown', 0.5, {'error': str(e)}
    
    def _keyword_based_classify(self, text: str) -> Tuple[str, float]:
        """
        Fallback keyword-based classification
        
        Args:
            text: Input text
            
        Returns:
            Tuple of (category, confidence)
        """
        scores = {}
        
        for category in self.scam_keywords.keys():
            scores[category] = self.keyword_match_score(text, category)
        
        if not scores or max(scores.values()) == 0:
            return 'safe', 0.5
        
        # Get best category
        best_category = max(scores, key=scores.get)
        confidence = scores[best_category]
        
        return best_category, confidence
    
    def _calculate_risk_score(self, category: str, confidence: float, features: Dict[str, Any]) -> float:
        """
        Calculate overall risk score based on category and features
        
        Args:
            category: Predicted category
            confidence: Model confidence
            features: Extracted text features
            
        Returns:
            Risk score 0.0 to 1.0
        """
        # Base risk by category
        category_risk = {
            'banking_scam': 0.9,
            'investment_scam': 0.85,
            'prize_scam': 0.8,
            'verification_scam': 0.75,
            'urgent_action': 0.7,
            'qr_phishing': 0.65,
            'safe': 0.1
        }
        
        base_risk = category_risk.get(category, 0.5)
        
        # Adjust by confidence
        adjusted_risk = base_risk * confidence
        
        # Boost for high urgency indicators
        if features.get('exclamation_count', 0) > 3:
            adjusted_risk = min(adjusted_risk * 1.1, 1.0)
        
        # Boost for many URLs
        if features.get('url_count', 0) > 2:
            adjusted_risk = min(adjusted_risk * 1.15, 1.0)
        
        return min(max(adjusted_risk, 0.0), 1.0)
    
    def _generate_explanation(self, category: str, risk_score: float, indicators: List[Dict]) -> str:
        """
        Generate user-friendly explanation
        
        Args:
            category: Scam category
            risk_score: Calculated risk score
            indicators: Detected indicators
            
        Returns:
            Human-readable explanation
        """
        if risk_score < 0.3:
            return "This content appears safe. No significant scam indicators detected."
        
        explanations = {
            'banking_scam': "This message contains suspicious banking requests. Legitimate banks never ask for your PIN, OTP, or password via messages.",
            'investment_scam': "This appears to be an investment scam promising unrealistic returns. Be cautious of 'get rich quick' schemes.",
            'prize_scam': "This is likely a fake prize or lottery notification. You cannot win a prize you never entered.",
            'verification_scam': "This appears to be a fake account verification request designed to steal your login credentials.",
            'urgent_action': "This message creates false urgency to trick you into taking immediate action without thinking.",
            'qr_phishing': "This QR code may lead to a malicious website. Verify the source before scanning."
        }
        
        base_explanation = explanations.get(category, "This content contains indicators of a potential scam.")
        
        # Add indicator details
        if indicators:
            indicator_types = [ind['type'].replace('_', ' ') for ind in indicators[:3]]
            return f"{base_explanation} Detected: {', '.join(indicator_types)}."
        
        return base_explanation
    
    def _save_model(self) -> None:
        """Save model to disk"""
        try:
            model_dir = os.path.dirname(self.model_path)
            if model_dir and not os.path.exists(model_dir):
                os.makedirs(model_dir)
            
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'vectorizer': self.vectorizer,
                    'label_encoder': self.label_encoder,
                    'categories': self.categories
                }, f)
            
            logger.info(f"Scam classifier saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving scam model: {str(e)}")
    
    def _load_model(self) -> None:
        """Load model from disk"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.vectorizer = data['vectorizer']
                    self.label_encoder = data['label_encoder']
                    if 'categories' in data:
                        self.categories = data['categories']
                
                logger.info(f"Scam classifier loaded from {self.model_path}")
            else:
                logger.warning(f"No pre-trained model found at {self.model_path}")
                
        except Exception as e:
            logger.error(f"Error loading scam model: {str(e)}")
            raise


# Singleton instance
_scam_classifier_instance = None

def get_scam_classifier() -> ScamClassifier:
    """Get or create singleton instance"""
    global _scam_classifier_instance
    if _scam_classifier_instance is None:
        _scam_classifier_instance = ScamClassifier()
    return _scam_classifier_instance