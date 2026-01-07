import re
import logging
from typing import List, Dict, Any
from .analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class ContentAnalyzer(BaseAnalyzer):
    """Analyzes file content using regex patterns."""
    
    DEFAULT_PATTERNS = {
        "aws_key": r"AKIA[0-9A-Z]{16}",
        "aws_secret": r"['\"]*[a-zA-Z0-9/+=]{40}['\"]*",
        "private_key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
        "db_connection": r"(mongodb|postgres|mysql|sqlite)://[a-zA-Z0-9]+:[a-zA-Z0-9]+@",
        "generic_secret": r"(password|passwd|secret|key|token|auth|admin)\s*[:=]\s*['\"]*([a-zA-Z0-9!@#$%^&*()_+]{4,})['\"]*",
        "ip_address": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "email": r"[\w\.-]+@[\w\.-]+\.\w+",
    }

    def __init__(self, custom_patterns: Dict[str, str] = None):
        patterns = self.DEFAULT_PATTERNS.copy()
        if custom_patterns:
            patterns.update(custom_patterns)
        
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE) 
            for name, pattern in patterns.items()
        }

    @property
    def name(self) -> str:
        return "content_analyzer"

    def analyze(self, content: bytes, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        try:
            # Try to decode content (with fallback)
            text = content.decode('utf-8', errors='ignore')
            
            for name, pattern in self.compiled_patterns.items():
                matches = pattern.finditer(text)
                for match in matches:
                    findings.append({
                        "type": name,
                        "match": match.group(0),
                        "line": text.count('\n', 0, match.start()) + 1,
                        "file": metadata.get("name"),
                        "share": metadata.get("share")
                    })
        except Exception as e:
            logger.error(f"Error analyzing content: {e}")
            
        return findings
        
class IOCAnalyzer(BaseAnalyzer):
    """Simple IOC (Indicator of Compromise) analyzer."""
    
    def __init__(self, iocs: List[str]):
        self.iocs = set(iocs)

    @property
    def name(self) -> str:
        return "ioc_analyzer"

    def analyze(self, content: bytes, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        text = content.decode('utf-8', errors='ignore')
        
        for ioc in self.iocs:
            if ioc in text:
                findings.append({
                    "type": "ioc_match",
                    "match": ioc,
                    "file": metadata.get("name"),
                    "share": metadata.get("share")
                })
        return findings
