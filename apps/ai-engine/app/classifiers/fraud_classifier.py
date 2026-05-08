# AYUSH WORK AREA
# Behavioral fraud pattern classifier
# Detects fraud patterns in text, transactions, and user behavior
# Focuses on social engineering and manipulation tactics

import os
import pickle
import logging
from typing import Dict, List, Tuple, Any
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import re
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("fraud_classifier")

class FraudClassifier:
    """
    Behavioral fraud pattern detector
    
    Identifies fraud indicators through:
    - Linguistic analysis (manipulation tactics)
    - Behavioral patterns (urgency, authority)
    - Statistical anomalies
    
    Uses Isolation Forest for anomaly detection
    combined with rule-based pattern matching.
    """
    
    def __init__(self, model_path: str = None):
        """
        Initialize fraud classifier
        
        Args:
            model_path: Path to serialized model
        """
        self.model_path = model_path or settings.FRAUD_MODEL_PATH
        self.model = None
        self.scaler = StandardScaler()
        
        # Fraud pattern databases
        self.manipulation_patterns = {
            'authority': [
                r'\b(official|authorized|verified|certified|government|bank|police)\b',
                r'\b(authority|representative|agent|officer|manager)\b'
            ],
            'urgency': [
                r'\b(urgent|immediate|now|today|asap|emergency|critical)\b',
                r'\b(within|hours?|minutes?|deadline|expire)\b'
            ],
            'scarcity': [
                r'\b(limited|exclusive|only|few|last|final|once)\b',
                r'\b(opportunity|offer|chance|available)\b'
            ],
            'social_proof': [
                r'\b(thousands|millions|users|customers|people|everyone)\b',
                r'\b(popular|trending|bestselling|recommended)\b'
            ],
            'reciprocity': [
                r'\b(free|gift|bonus|reward|prize|complimentary)\b',
                r'\b(give|offer|provide|send|receive)\b'
            ],
            'fear': [
                r'\b(threat|danger|risk|warning|alert|suspended|blocked)\b',
                r'\b(lose|penalty|fine|legal|action|consequence)\b'
            ]
        }
        
        # Financial fraud indicators
        self.financial_patterns = [
            r'\b(transfer|payment|wire|remittance|transaction)\b',
            r'\b(account|bank|routing|ifsc|swift|iban)\b',
            r'\b(amount|sum|fee|charge|commission)\b',
            r'\b(investment|return|profit|interest|dividend)\b'
        ]
    
    def extract_behavioral_features(self, text: str) -> np.ndarray:
        """
        Extract behavioral and linguistic features
        
        Args:
            text: Input text
            
        Returns:
            Feature vector
        """
        features = {}
        text_lower = text.lower()
        
        # Count manipulation tactics
        for tactic, patterns in self.manipulation_patterns.items():
            count = 0
            for pattern in patterns:
                count += len(re.findall(pattern, text_lower))
            features[f'{tactic}_count'] = count
        
        # Financial indicators
        financial_count = 0
        for pattern in self.financial_patterns:
            financial_count += len(re.findall(pattern, text_lower))
        features['financial_count'] = financial_count
        
        # Linguistic features
        words = text.split()
        features['word_count'] = len(words)
        features['avg_word_length'] = np.mean([len(w) for w in words]) if words else 0
        features['uppercase_ratio'] = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        features['exclamation_ratio'] = text.count('!') / max(len(text), 1)
        features['question_ratio'] = text.count('?') / max(len(text), 1)
        
        # Readability indicators
        features['sentence_count'] = len(re.split(r'[.!?]+', text))
        features['avg_sentence_length'] = features['word_count'] / max(features['sentence_count'], 1)
        
        # Personal pronouns (social engineering indicator)
        personal_pronouns = len(re.findall(r'\b(you|your|yours|we|our|us|i|me|my)\b', text_lower))
        features['pronoun_ratio'] = personal_pronouns / max(features['word_count'], 1)
        
        # Numeric density
        digits = sum(1 for c in text if c.isdigit())
        features['digit_density'] = digits / max(len(text), 1)
        
        # Convert to array
        feature_vector = np.array(list(features.values()), dtype=np.float64)
        
        return feature_vector
    
    def detect_manipulation_tactics(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect specific manipulation tactics in text
        
        Args:
            text: Input text
            
        Returns:
            List of detected tactics
        """
        tactics = []
        text_lower = text.lower()
        
        for tactic, patterns in self.manipulation_patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, text_lower)
                matches.extend(found)
            
            if matches:
                tactics.append({
                    'tactic': tactic,
                    'count': len(matches),
                    'examples': list(set(matches))[:3],
                    'severity': self._calculate_tactic_severity(tactic, len(matches))
                })
        
        return sorted(tactics, key=lambda x: x['severity'], reverse=True)
    
    def _calculate_tactic_severity(self, tactic: str, count: int) -> float:
        """
        Calculate severity score for a manipulation tactic
        
        Args:
            tactic: Tactic name
            count: Number of occurrences
            
        Returns:
            Severity score 0.0 to 1.0
        """
        # High-severity tactics
        high_severity = ['fear', 'urgency', 'authority']
        
        base_severity = 0.7 if tactic in high_severity else 0.5
        
        # Scale by count (log scale)
        count_factor = min(np.log1p(count) / 2, 1.0)
        
        return base_severity * (0.5 + 0.5 * count_factor)
    
    def train(self, X: np.ndarray, y: np.ndarray) -> None:
        """
        Train fraud detection model
        
        Uses Isolation Forest for anomaly detection
        
        Args:
            X: Feature matrix
            y: Labels (0 = normal, 1 = fraud)
        """
        logger.info(f"Training fraud classifier on {len(X)} samples")
        
        try:
            # Fit scaler
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                max_samples='auto',
                random_state=42,
                n_jobs=-1
            )
            
            self.model.fit(X_scaled)
            
            logger.info("Fraud classifier trained successfully")
            self._save_model()
            
        except Exception as e:
            logger.error(f"Error training fraud classifier: {str(e)}")
            raise
    
    def predict(self, text: str) -> Tuple[float, float, Dict[str, Any]]:
        """
        Predict fraud probability
        
        Args:
            text: Text to analyze
            
        Returns:
            Tuple of (fraud_score, confidence, metadata)
        """
        try:
            # Extract features
            features = self.extract_behavioral_features(text)
            
            # Detect manipulation tactics
            tactics = self.detect_manipulation_tactics(text)
            
            # Calculate base fraud score from tactics
            tactic_score = 0.0
            if tactics:
                tactic_score = sum(t['severity'] for t in tactics) / len(tactics)
            
            # ML-based anomaly detection
            ml_score = 0.5
            confidence = 0.5
            
            if self.model:
                try:
                    # Scale features
                    X_scaled = self.scaler.transform([features])
                    
                    # Get anomaly score (-1 = anomaly, 1 = normal)
                    prediction = self.model.predict(X_scaled)[0]
                    anomaly_score = self.model.score_samples(X_scaled)[0]
                    
                    # Convert to 0-1 scale (higher = more fraudulent)
                    ml_score = 1.0 - (anomaly_score + 1) / 2
                    ml_score = max(0.0, min(1.0, ml_score))
                    
                    # Confidence based on anomaly score magnitude
                    confidence = min(abs(anomaly_score) * 2, 1.0)
                    
                except Exception as e:
                    logger.error(f"ML prediction failed: {str(e)}")
            
            # Combine tactic-based and ML scores
            fraud_score = 0.6 * tactic_score + 0.4 * ml_score
            
            # Boost for multiple high-severity tactics
            high_severity_count = sum(1 for t in tactics if t['severity'] > 0.7)
            if high_severity_count >= 2:
                fraud_score = min(fraud_score * 1.2, 1.0)
            
            metadata = {
                'fraud_score': fraud_score,
                'tactic_score': tactic_score,
                'ml_score': ml_score,
                'confidence': confidence,
                'manipulation_tactics': tactics,
                'feature_summary': {
                    'word_count': features[6],
                    'financial_indicators': features[5],
                    'urgency_count': features[1],
                    'fear_count': features[5]
                }
            }
            
            logger.debug(f"Fraud prediction: score={fraud_score:.4f}, confidence={confidence:.4f}")
            
            return fraud_score, confidence, metadata
            
        except Exception as e:
            logger.error(f"Error predicting fraud: {str(e)}")
            return 0.5, 0.0, {'error': str(e)}
    
    def analyze_transaction_pattern(self, transaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze transaction patterns for fraud
        
        Args:
            transaction_data: Dictionary with transaction details
            
        Returns:
            Fraud analysis results
        """
        # Extract features from transaction
        features = []
        
        # Amount features
        amount = transaction_data.get('amount', 0)
        features.append(np.log1p(amount))  # Log scale
        
        # Time features
        timestamp = transaction_data.get('timestamp')
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp)
                features.append(dt.hour)  # Hour of day
                features.append(dt.weekday())  # Day of week
            except:
                features.extend([0, 0])
        else:
            features.extend([0, 0])
        
        # Frequency features
        features.append(transaction_data.get('frequency_24h', 0))
        
        # Location features
        features.append(1 if transaction_data.get('is_international') else 0)
        
        # Convert to array
        X = np.array([features], dtype=np.float64)
        
        # Predict
        if self.model:
            try:
                X_scaled = self.scaler.transform(X)
                prediction = self.model.predict(X_scaled)[0]
                anomaly_score = self.model.score_samples(X_scaled)[0]
                
                is_fraudulent = prediction == -1
                fraud_probability = 1.0 - (anomaly_score + 1) / 2
                
                return {
                    'is_fraudulent': is_fraudulent,
                    'fraud_probability': max(0.0, min(1.0, fraud_probability)),
                    'anomaly_score': anomaly_score,
                    'transaction_id': transaction_data.get('id')
                }
            except Exception as e:
                logger.error(f"Transaction analysis failed: {str(e)}")
        
        return {
            'is_fraudulent': False,
            'fraud_probability': 0.5,
            'error': 'Model not available'
        }
    
    def _save_model(self) -> None:
        """Save model to disk"""
        try:
            model_dir = os.path.dirname(self.model_path)
            if model_dir and not os.path.exists(model_dir):
                os.makedirs(model_dir)
            
            with open(self.model_path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler
                }, f)
            
            logger.info(f"Fraud classifier saved to {self.model_path}")
            
        except Exception as e:
            logger.error(f"Error saving fraud model: {str(e)}")
    
    def _load_model(self) -> None:
        """Load model from disk"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.scaler = data['scaler']
                
                logger.info(f"Fraud classifier loaded from {self.model_path}")
            else:
                logger.warning(f"No pre-trained model found at {self.model_path}")
                
        except Exception as e:
            logger.error(f"Error loading fraud model: {str(e)}")
            raise


# Singleton instance
_fraud_classifier_instance = None

def get_fraud_classifier() -> FraudClassifier:
    """Get or create singleton instance"""
    global _fraud_classifier_instance
    if _fraud_classifier_instance is None:
        _fraud_classifier_instance = FraudClassifier()
    return _fraud_classifier_instance