# AYUSH WORK AREA
# Unified risk scoring classifier
# Aggregates signals from multiple classifiers into single risk score
# Implements CONTEXT.md risk assessment methodology

import logging
from typing import Dict, List, Tuple, Any, Optional
import numpy as np
from datetime import datetime
import json

# Local imports
from app.utils.logger import setup_logger
from app.config import settings
from .phishing_classifier import get_phishing_classifier
from .scam_classifier import get_scam_classifier
from .fraud_classifier import get_fraud_classifier

logger = setup_logger("risk_classifier")

class RiskClassifier:
    """
    Unified risk assessment classifier
    
    Aggregates predictions from multiple specialized classifiers:
    - Phishing classifier (URL analysis)
    - Scam classifier (text analysis)
    - Fraud classifier (behavioral patterns)
    
    Produces a unified risk score (0.0-1.0) with:
    - Risk level categorization (SAFE, LOW, MEDIUM, HIGH, CRITICAL)
    - Detailed explanation
    - Recommended actions
    """
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        'SAFE': 0.2,
        'LOW': 0.4,
        'MEDIUM': 0.6,
        'HIGH': 0.8,
        'CRITICAL': 0.9
    }
    
    # Category weights for aggregation
    CATEGORY_WEIGHTS = {
        'phishing': 0.4,
        'scam': 0.35,
        'fraud': 0.25
    }
    
    def __init__(self):
        """Initialize risk classifier with sub-classifiers"""
        self.phishing_classifier = get_phishing_classifier()
        self.scam_classifier = get_scam_classifier()
        self.fraud_classifier = get_fraud_classifier()
        
        logger.info("Risk classifier initialized with all sub-classifiers")
    
    def assess_url_risk(self, url: str) -> Dict[str, Any]:
        """
        Comprehensive risk assessment for a URL
        
        Args:
            url: URL to assess
            
        Returns:
            Comprehensive risk assessment dictionary
        """
        logger.info(f"Assessing URL risk: {url[:100]}...")
        
        results = {}
        
        # 1. Phishing analysis
        try:
            phishing_score, phishing_conf, phishing_meta = self.phishing_classifier.predict(url)
            results['phishing'] = {
                'score': phishing_score,
                'confidence': phishing_conf,
                'metadata': phishing_meta
            }
        except Exception as e:
            logger.error(f"Phishing analysis failed: {str(e)}")
            results['phishing'] = {'score': 0.5, 'confidence': 0.0, 'error': str(e)}
        
        # 2. Extract text from URL for scam analysis
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            text_content = f"{parsed.path} {parsed.query}"
            
            if text_content.strip():
                scam_category, scam_score, scam_meta = self.scam_classifier.predict(text_content)
                results['scam'] = {
                    'category': scam_category,
                    'score': scam_score,
                    'metadata': scam_meta
                }
            else:
                results['scam'] = {'score': 0.0, 'category': 'safe'}
        except Exception as e:
            logger.error(f"Scam analysis failed: {str(e)}")
            results['scam'] = {'score': 0.5, 'error': str(e)}
        
        # 3. Aggregate risk score
        aggregated_score = self._aggregate_scores(results)
        
        # 4. Determine risk level
        risk_level = self._get_risk_level(aggregated_score)
        
        # 5. Generate explanation and recommendations
        explanation = self._generate_url_explanation(aggregated_score, risk_level, results)
        recommendations = self._generate_recommendations(risk_level, results)
        
        return {
            'url': url,
            'risk_score': aggregated_score,
            'risk_level': risk_level,
            'explanation': explanation,
            'recommendations': recommendations,
            'detailed_results': results,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def assess_text_risk(self, text: str) -> Dict[str, Any]:
        """
        Comprehensive risk assessment for text content
        
        Args:
            text: Text to assess (from OCR, SMS, WhatsApp, etc.)
            
        Returns:
            Comprehensive risk assessment dictionary
        """
        logger.info(f"Assessing text risk (length: {len(text)})")
        
        results = {}
        
        # 1. Scam analysis
        try:
            scam_category, scam_score, scam_meta = self.scam_classifier.predict(text)
            results['scam'] = {
                'category': scam_category,
                'score': scam_score,
                'metadata': scam_meta
            }
        except Exception as e:
            logger.error(f"Scam analysis failed: {str(e)}")
            results['scam'] = {'score': 0.5, 'error': str(e)}
        
        # 2. Fraud pattern detection
        try:
            fraud_score, fraud_conf, fraud_meta = self.fraud_classifier.predict(text)
            results['fraud'] = {
                'score': fraud_score,
                'confidence': fraud_conf,
                'metadata': fraud_meta
            }
        except Exception as e:
            logger.error(f"Fraud analysis failed: {str(e)}")
            results['fraud'] = {'score': 0.5, 'confidence': 0.0, 'error': str(e)}
        
        # 3. Check for URLs in text
        import re
        urls = re.findall(r'https?://\S+', text)
        if urls:
            url_risks = []
            for url in urls[:3]:  # Limit to first 3 URLs
                url_result = self.assess_url_risk(url)
                url_risks.append(url_result['risk_score'])
            
            if url_risks:
                results['embedded_urls'] = {
                    'count': len(urls),
                    'max_risk': max(url_risks),
                    'avg_risk': sum(url_risks) / len(url_risks)
                }
        
        # 4. Aggregate risk score
        aggregated_score = self._aggregate_scores(results)
        
        # 5. Determine risk level
        risk_level = self._get_risk_level(aggregated_score)
        
        # 6. Generate explanation
        explanation = self._generate_text_explanation(aggregated_score, risk_level, results)
        recommendations = self._generate_recommendations(risk_level, results)
        
        return {
            'text_preview': text[:200] + "..." if len(text) > 200 else text,
            'risk_score': aggregated_score,
            'risk_level': risk_level,
            'explanation': explanation,
            'recommendations': recommendations,
            'detailed_results': results,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _aggregate_scores(self, results: Dict[str, Any]) -> float:
        """
        Aggregate scores from multiple classifiers
        
        Uses weighted average with boost for high-risk indicators
        
        Args:
            results: Dictionary of classifier results
            
        Returns:
            Aggregated risk score 0.0 to 1.0
        """
        weighted_sum = 0.0
        total_weight = 0.0
        
        for category, weight in self.CATEGORY_WEIGHTS.items():
            if category in results:
                score = results[category].get('score', 0.5)
                confidence = results[category].get('confidence', 1.0)
                
                # Weight by confidence
                adjusted_weight = weight * confidence
                weighted_sum += score * adjusted_weight
                total_weight += adjusted_weight
        
        # Calculate base aggregated score
        if total_weight > 0:
            aggregated = weighted_sum / total_weight
        else:
            aggregated = 0.5
        
        # Apply boosts for specific high-risk indicators
        
        # Boost if multiple classifiers agree on high risk
        high_risk_count = sum(
            1 for cat in ['phishing', 'scam', 'fraud']
            if cat in results and results[cat].get('score', 0) > 0.7
        )
        
        if high_risk_count >= 2:
            aggregated = min(aggregated * 1.2, 1.0)
        
        # Boost for embedded high-risk URLs
        if 'embedded_urls' in results:
            if results['embedded_urls'].get('max_risk', 0) > 0.8:
                aggregated = min(aggregated * 1.15, 1.0)
        
        return min(max(aggregated, 0.0), 1.0)
    
    def _get_risk_level(self, score: float) -> str:
        """
        Convert risk score to categorical level
        
        Args:
            score: Risk score 0.0 to 1.0
            
        Returns:
            Risk level string
        """
        if score < self.RISK_THRESHOLDS['SAFE']:
            return 'SAFE'
        elif score < self.RISK_THRESHOLDS['LOW']:
            return 'LOW'
        elif score < self.RISK_THRESHOLDS['MEDIUM']:
            return 'MEDIUM'
        elif score < self.RISK_THRESHOLDS['HIGH']:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def _generate_url_explanation(self, score: float, level: str, results: Dict) -> str:
        """Generate explanation for URL risk assessment"""
        if level == 'SAFE':
            return "This URL appears safe based on our analysis. No significant phishing or scam indicators detected."
        
        explanations = []
        
        # Phishing indicators
        if 'phishing' in results and results['phishing'].get('score', 0) > 0.5:
            meta = results['phishing'].get('metadata', {})
            if meta.get('has_suspicious_tld'):
                explanations.append("uses a suspicious domain extension")
            if meta.get('has_ip_address'):
                explanations.append("uses an IP address instead of domain name")
            if not meta.get('has_https'):
                explanations.append("lacks HTTPS encryption")
        
        # Scam indicators
        if 'scam' in results and results['scam'].get('score', 0) > 0.5:
            category = results['scam'].get('category', 'unknown')
            if category != 'safe':
                explanations.append(f"contains {category.replace('_', ' ')} patterns")
        
        base = f"This URL shows indicators of potential threats ("
        if explanations:
            return base + ", ".join(explanations) + "). Exercise caution."
        else:
            return f"This URL has a {level.lower()} risk score. Proceed with caution."
    
    def _generate_text_explanation(self, score: float, level: str, results: Dict) -> str:
        """Generate explanation for text risk assessment"""
        if level == 'SAFE':
            return "This content appears safe. No significant scam or fraud indicators detected."
        
        explanations = []
        
        # Scam category
        if 'scam' in results:
            category = results['scam'].get('category', 'unknown')
            if category != 'safe':
                explanations.append(f"matches {category.replace('_', ' ')} patterns")
        
        # Fraud indicators
        if 'fraud' in results and results['fraud'].get('score', 0) > 0.5:
            explanations.append("contains fraudulent language patterns")
        
        # Embedded URLs
        if 'embedded_urls' in results:
            if results['embedded_urls'].get('max_risk', 0) > 0.7:
                explanations.append("contains suspicious links")
        
        base = f"This message shows indicators of potential scams ("
        if explanations:
            return base + ", ".join(explanations) + "). Do not share personal information or click links."
        else:
            return f"This content has a {level.lower()} risk score. Be cautious before taking any action."
    
    def _generate_recommendations(self, level: str, results: Dict) -> List[str]:
        """Generate actionable recommendations based on risk level"""
        recommendations = []
        
        if level in ['HIGH', 'CRITICAL']:
            recommendations.extend([
                "Do not click any links in this content",
                "Do not provide personal or financial information",
                "Report this as suspicious to the platform",
                "Delete this message immediately"
            ])
            
            if 'phishing' in results and results['phishing'].get('score', 0) > 0.7:
                recommendations.append("Verify the sender's identity through official channels")
            
            if 'scam' in results:
                category = results['scam'].get('category', '')
                if category == 'banking_scam':
                    recommendations.append("Contact your bank directly using official contact details")
                elif category == 'investment_scam':
                    recommendations.append("Research any investment opportunity thoroughly before proceeding")
        
        elif level == 'MEDIUM':
            recommendations.extend([
                "Verify the source before taking any action",
                "Do not share sensitive information",
                "Be cautious of urgency or pressure tactics"
            ])
        
        elif level == 'LOW':
            recommendations.append("Exercise normal caution when interacting with this content")
        
        else:  # SAFE
            recommendations.append("Continue practicing good security hygiene")
        
        return recommendations
    
    def get_risk_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about risk assessment
        
        Returns:
            Dictionary with classifier statistics
        """
        return {
            'thresholds': self.RISK_THRESHOLDS,
            'weights': self.CATEGORY_WEIGHTS,
            'classifiers': {
                'phishing': 'active' if self.phishing_classifier.model else 'not_loaded',
                'scam': 'active' if self.scam_classifier.model else 'not_loaded',
                'fraud': 'active' if self.fraud_classifier.model else 'not_loaded'
            }
        }


# Singleton instance
_risk_classifier_instance = None

def get_risk_classifier() -> RiskClassifier:
    """Get or create singleton instance"""
    global _risk_classifier_instance
    if _risk_classifier_instance is None:
        _risk_classifier_instance = RiskClassifier()
    return _risk_classifier_instance