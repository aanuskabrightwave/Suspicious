# AYUSH WORK AREA
# APK scanner module for malware analysis
# Implements CONTEXT.md: "App Safety: Malicious APK and overlay attack detection"
# Focuses on static analysis of APK files without execution

import os
import logging
import zipfile
import xml.etree.ElementTree as ET
import re
from typing import Dict, List, Tuple, Optional, Any
import hashlib
from datetime import datetime

# Local imports
from app.utils.logger import setup_logger
from app.config import settings

logger = setup_logger("apk_scanner")

class APKScanner:
    """
    Static APK analysis scanner for malware detection
    
    This class implements the first stage of APK analysis:
    1. APK file validation and extraction
    2. Manifest analysis (permissions, components)
    3. Certificate verification
    4. Resource analysis (suspicious files)
    5. Heuristic-based risk scoring
    
    Security Note: This is static analysis only - no code execution.
    For dynamic analysis, a sandbox environment would be required.
    """
    
    def __init__(self):
        """Initialize APK scanning rules"""
        self._initialize_rules()
        logger.info("APKScanner initialized")
    
    def _initialize_rules(self):
        """Initialize APK scanning rules and patterns"""
        # High-risk permissions
        self.high_risk_permissions = {
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_PHONE_STATE',
            'android.permission.CALL_PHONE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.REQUEST_INSTALL_PACKAGES',
            'android.permission.SYSTEM_ALERT_WINDOW'
        }
        
        # Medium-risk permissions
        self.medium_risk_permissions = {
            'android.permission.INTERNET',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.WAKE_LOCK',
            'android.permission.VIBRATE'
        }
        
        # Suspicious package names
        self.suspicious_packages = [
            'com.android.',
            'android.',
            'system.',
            'google.',
            'facebook.',
            'whatsapp.',
            'telegram.'
        ]
        
        # Known malicious patterns in code/resources
        self.malicious_patterns = {
            'sms': ['sendTextMessage', ' SmsManager', 'sms://'],
            'call': ['telecom', 'TelecomManager', 'call:', 'tel:'],
            'location': ['FusedLocation', 'LocationManager', 'getLatitude'],
            'camera': ['CameraDevice', 'MediaRecorder', 'SurfaceTexture'],
            'keylogger': ['onKeyDown', 'onKeyUp', 'dispatchKeyEvent'],
            'overlay': ['SYSTEM_ALERT_WINDOW', 'TYPE_APPLICATION_OVERLAY'],
            'device_id': ['getDeviceId', 'getSubscriberId', 'getSimSerialNumber']
        }
        
        # Suspicious file extensions
        self.suspicious_files = [
            '.dex', '.so', '.jar', '.apk', '.zip', '.rar',
            'classes.dex', 'libnative.so', 'assets/data.bin'
        ]
    
    def scan_apk(self, apk_data: str) -> Dict[str, Any]:
        """
        Scan an APK file for malicious indicators
        
        Args:
            apk_data: Base64-encoded APK data
            
        Returns:
            Dictionary with scan results including:
                - risk_score: Overall risk score (0.0-1.0)
                - category: Detected threat category
                - explanation: User-friendly explanation
                - details: Technical details
        """
        start_time = datetime.utcnow()
        
        try:
            # Decode APK data
            import base64
            apk_bytes = base64.b64decode(apk_data)
            
            # Validate APK size
            if len(apk_bytes) > settings.MAX_APK_SIZE_MB * 1024 * 1024:
                raise ValueError(f"APK too large: {len(apk_bytes)} bytes (max: {settings.MAX_APK_SIZE_MB}MB)")
            
            # Create temporary file
            temp_apk_path = f"/tmp/apk_scan_{hash(apk_bytes[:8])}.apk"
            with open(temp_apk_path, 'wb') as f:
                f.write(apk_bytes)
            
            try:
                # Analyze APK
                manifest_analysis = self._analyze_manifest(temp_apk_path)
                certificate_analysis = self._analyze_certificate(temp_apk_path)
                resource_analysis = self._analyze_resources(temp_apk_path)
                package_analysis = self._analyze_package_name(temp_apk_path)
                
                # Calculate risk score
                risk_score = self._calculate_risk_score(
                    manifest_analysis,
                    certificate_analysis,
                    resource_analysis,
                    package_analysis
                )
                
                # Determine category
                category = self._determine_category(risk_score, manifest_analysis)
                
                # Generate explanation
                explanation = self._generate_explanation(
                    risk_score, 
                    category, 
                    manifest_analysis,
                    resource_analysis
                )
                
                # Clean up
                os.remove(temp_apk_path)
                
                return {
                    "risk_score": risk_score,
                    "category": category,
                    "explanation": explanation,
                    "details": {
                        "manifest_analysis": manifest_analysis,
                        "certificate_analysis": certificate_analysis,
                        "resource_analysis": resource_analysis,
                        "package_analysis": package_analysis,
                        "analysis_time": (datetime.utcnow() - start_time).total_seconds(),
                        "apk_hash": hashlib.sha256(apk_bytes).hexdigest()[:16]
                    }
                }
                
            except Exception as e:
                raise e
            finally:
                # Ensure cleanup even on error
                if os.path.exists(temp_apk_path):
                    os.remove(temp_apk_path)
                    
        except Exception as e:
            logger.error(f"APK scanning failed: {str(e)}", exc_info=True)
            return {
                "risk_score": 0.5,
                "category": "error",
                "explanation": "Failed to analyze APK. Please try again.",
                "details": {
                    "error": str(e),
                    "analysis_time": (datetime.utcnow() - start_time).total_seconds()
                }
            }
    
    def _analyze_manifest(self, apk_path: str) -> Dict[str, Any]:
        """
        Analyze AndroidManifest.xml for suspicious elements
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dictionary with manifest analysis results
        """
        try:
            # Extract AndroidManifest.xml
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if 'AndroidManifest.xml' not in zf.namelist():
                    return {"permissions": [], "activities": [], "services": [], "receivers": [], "error": "Manifest not found"}
                
                manifest_data = zf.read('AndroidManifest.xml')
                
                # Convert binary XML to readable format (simplified)
                # In production, use axmlparser or similar library
                manifest_text = manifest_data.decode('utf-8', errors='ignore')
                
                # Extract permissions
                permissions = re.findall(r'android:name\s*=\s*"([^"]+)"', manifest_text)
                high_risk_perms = [p for p in permissions if p in self.high_risk_permissions]
                medium_risk_perms = [p for p in permissions if p in self.medium_risk_permissions]
                
                # Extract components
                activities = re.findall(r'<activity\s+android:name\s*=\s*"([^"]+)"', manifest_text)
                services = re.findall(r'<service\s+android:name\s*=\s*"([^"]+)"', manifest_text)
                receivers = re.findall(r'<receiver\s+android:name\s*=\s*"([^"]+)"', manifest_text)
                
                return {
                    "permissions": permissions,
                    "high_risk_permissions": high_risk_perms,
                    "medium_risk_permissions": medium_risk_perms,
                    "activities": activities,
                    "services": services,
                    "receivers": receivers,
                    "total_permissions": len(permissions),
                    "high_risk_count": len(high_risk_perms),
                    "medium_risk_count": len(medium_risk_perms)
                }
                
        except Exception as e:
            logger.error(f"Manifest analysis failed: {str(e)}")
            return {"error": str(e)}
    
    def _analyze_certificate(self, apk_path: str) -> Dict[str, Any]:
        """
        Analyze APK certificate for validity and issuer
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dictionary with certificate analysis results
        """
        try:
            # Extract certificate information
            # In production, use apksigner or similar tool
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if 'META-INF/' not in zf.namelist():
                    return {"valid": False, "issuer": "Unknown", "error": "No META-INF directory"}
                
                # Look for .RSA or .DSA files
                cert_files = [f for f in zf.namelist() if f.endswith(('.RSA', '.DSA', '.EC'))]
                
                if not cert_files:
                    return {"valid": False, "issuer": "Unknown", "warning": "No certificate found"}
                
                # Simplified certificate analysis
                # In production, parse actual certificate data
                cert_file = cert_files[0]
                cert_data = zf.read(cert_file)
                
                # Check certificate validity (simplified)
                is_valid = True
                issuer = "Unknown"
                
                # Basic heuristics
                if b'Google' in cert_data or b'Android' in cert_data:
                    issuer = "Google/Android"
                elif b'Amazon' in cert_data:
                    issuer = "Amazon"
                elif b'Facebook' in cert_data:
                    issuer = "Facebook"
                
                return {
                    "valid": is_valid,
                    "issuer": issuer,
                    "cert_file": cert_file,
                    "cert_size": len(cert_data),
                    "has_signature": True
                }
                
        except Exception as e:
            logger.error(f"Certificate analysis failed: {str(e)}")
            return {"error": str(e)}
    
    def _analyze_resources(self, apk_path: str) -> Dict[str, Any]:
        """
        Analyze APK resources for suspicious files and patterns
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dictionary with resource analysis results
        """
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                file_list = zf.namelist()
                
                # Find suspicious files
                suspicious_files = []
                for file_path in file_list:
                    for pattern in self.suspicious_files:
                        if pattern in file_path.lower():
                            suspicious_files.append(file_path)
                
                # Search for malicious patterns in code
                malicious_indicators = []
                for file_path in file_list:
                    if file_path.endswith(('.smali', '.dex', '.xml', '.txt')):
                        try:
                            content = zf.read(file_path).decode('utf-8', errors='ignore')
                            
                            for category, patterns in self.malicious_patterns.items():
                                for pattern in patterns:
                                    if pattern.lower() in content.lower():
                                        malicious_indicators.append({
                                            "category": category,
                                            "pattern": pattern,
                                            "file": file_path,
                                            "context": content[:200] + "..." if len(content) > 200 else content
                                        })
                        except Exception as e:
                            logger.debug(f"Could not read {file_path}: {str(e)}")
                
                return {
                    "suspicious_files": suspicious_files,
                    "malicious_indicators": malicious_indicators,
                    "total_files": len(file_list),
                    "suspicious_file_count": len(suspicious_files),
                    "malicious_indicator_count": len(malicious_indicators)
                }
                
        except Exception as e:
            logger.error(f"Resource analysis failed: {str(e)}")
            return {"error": str(e)}
    
    def _analyze_package_name(self, apk_path: str) -> Dict[str, Any]:
        """
        Analyze APK package name for suspicious patterns
        
        Args:
            apk_path: Path to APK file
            
        Returns:
            Dictionary with package analysis results
        """
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if 'AndroidManifest.xml' not in zf.namelist():
                    return {"package_name": "unknown", "suspicious": False}
                
                manifest_data = zf.read('AndroidManifest.xml').decode('utf-8', errors='ignore')
                
                # Extract package name
                package_match = re.search(r'package\s*=\s*"([^"]+)"', manifest_data)
                package_name = package_match.group(1) if package_match else "unknown"
                
                # Check for suspicious patterns
                suspicious = False
                suspicious_reasons = []
                
                for pattern in self.suspicious_packages:
                    if pattern in package_name.lower():
                        suspicious = True
                        suspicious_reasons.append(f"Contains suspicious prefix: {pattern}")
                
                # Check for common obfuscation patterns
                if re.search(r'\b[a-z]{2,3}\d{2,}\b', package_name):
                    suspicious = True
                    suspicious_reasons.append("Contains obfuscated naming pattern")
                
                if len(package_name.split('.')) < 3:
                    suspicious = True
                    suspicious_reasons.append("Package name too short")
                
                return {
                    "package_name": package_name,
                    "suspicious": suspicious,
                    "reasons": suspicious_reasons,
                    "parts": package_name.split('.')
                }
                
        except Exception as e:
            logger.error(f"Package analysis failed: {str(e)}")
            return {"error": str(e)}
    
    def _calculate_risk_score(
        self, 
        manifest_analysis: Dict[str, Any],
        certificate_analysis: Dict[str, Any],
        resource_analysis: Dict[str, Any],
        package_analysis: Dict[str, Any]
    ) -> float:
        """
        Calculate overall risk score from analysis results
        
        Args:
            Analysis result dictionaries
            
        Returns:
            Risk score 0.0-1.0
        """
        score = 0.0
        
        # Manifest analysis scoring
        high_risk_perms = manifest_analysis.get("high_risk_count", 0)
        medium_risk_perms = manifest_analysis.get("medium_risk_count", 0)
        total_perms = manifest_analysis.get("total_permissions", 0)
        
        # High-risk permissions (each worth 0.15)
        score += high_risk_perms * 0.15
        
        # Medium-risk permissions
        score += medium_risk_perms * 0.05
        
        # Many permissions (over 20)
        if total_perms > 20:
            score += 0.2
        
        # Certificate analysis
        if certificate_analysis.get("valid") is False:
            score += 0.3
        
        # Resource analysis
        suspicious_files = resource_analysis.get("suspicious_file_count", 0)
        malicious_indicators = resource_analysis.get("malicious_indicator_count", 0)
        
        # Suspicious files (each worth 0.1)
        score += suspicious_files * 0.1
        
        # Malicious indicators
        score += malicious_indicators * 0.15
        
        # Package analysis
        if package_analysis.get("suspicious"):
            score += 0.2
        
        # Normalize to 0-1 range
        risk_score = min(score, 1.0)
        
        return risk_score
    
    def _determine_category(self, risk_score: float, manifest_analysis: Dict[str, Any]) -> str:
        """
        Determine threat category based on risk score and analysis
        
        Args:
            risk_score: Calculated risk score
            manifest_analysis: Manifest analysis results
            
        Returns:
            Threat category string
        """
        if risk_score >= 0.8:
            return "malware"
        elif risk_score >= 0.6:
            return "spyware"
        elif risk_score >= 0.4:
            return "potentially_harmful"
        elif risk_score >= 0.2:
            return "low_risk"
        else:
            return "safe"
    
    def _generate_explanation(
        self, 
        risk_score: float, 
        category: str, 
        manifest_analysis: Dict[str, Any],
        resource_analysis: Dict[str, Any]
    ) -> str:
        """
        Generate user-friendly explanation for APK scan results
        
        Args:
            risk_score: Calculated risk score
            category: Threat category
            manifest_analysis: Manifest analysis results
            resource_analysis: Resource analysis results
            
        Returns:
            Human-readable explanation
        """
        if risk_score < 0.2:
            return "This APK appears safe. No significant security concerns detected."
        
        explanations = {
            "malware": "This APK shows strong indicators of malware. It requests dangerous permissions and contains suspicious code patterns.",
            "spyware": "This APK appears to be spyware. It has permissions to access sensitive data and may collect personal information without consent.",
            "potentially_harmful": "This APK has some potentially harmful characteristics. Review permissions carefully before installation.",
            "low_risk": "This APK has minor security concerns but is likely safe for most users.",
            "safe": "This APK appears safe. No significant security concerns detected."
        }
        
        base_explanation = explanations.get(category, "This APK has security concerns that require attention.")
        
        # Add specific details
        details = []
        
        # Permissions
        high_perms = manifest_analysis.get("high_risk_permissions", [])
        if high_perms:
            details.append(f"Requests {len(high_perms)} high-risk permissions: {', '.join(high_perms[:3])}")
        
        # Suspicious files
        suspicious_files = resource_analysis.get("suspicious_files", [])
        if suspicious_files:
            details.append(f"Contains {len(suspicious_files)} suspicious files")
        
        # Malicious indicators
        malicious_indicators = resource_analysis.get("malicious_indicators", [])
        if malicious_indicators:
            details.append(f"Contains {len(malicious_indicators)} malicious code patterns")
        
        if details:
            return f"{base_explanation} Detected: {', '.join(details)}."
        
        return base_explanation


# Singleton instance
_apk_scanner_instance = None

def get_apk_scanner() -> APKScanner:
    """Get or create singleton instance"""
    global _apk_scanner_instance
    if _apk_scanner_instance is None:
        _apk_scanner_instance = APKScanner()
    return _apk_scanner_instance