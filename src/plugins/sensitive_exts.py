from typing import Any, Dict, List
from src.analysis.analyzer import BaseAnalyzer

class SensitiveFileExtPlugin(BaseAnalyzer):
    """Detects sensitive file extensions."""
    
    SENSITIVE_EXTS = {'.bak', '.pfx', '.p12', '.sql', '.config', '.env', '.yaml', '.yml'}

    @property
    def name(self) -> str:
        return "sensitive_file_ext_plugin"

    def analyze(self, content: bytes, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = []
        file_name = metadata.get("name", "").lower()
        
        for ext in self.SENSITIVE_EXTS:
            if file_name.endswith(ext):
                findings.append({
                    "type": "sensitive_extension",
                    "match": ext,
                    "file": file_name,
                    "share": metadata.get("share"),
                    "analyzer": "plugin"
                })
                
        return findings
