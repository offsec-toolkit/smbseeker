from abc import ABC, abstractmethod
from typing import Any, Dict, List

class BaseAnalyzer(ABC):
    """Base class for all analyzers and plugins."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        pass

    @abstractmethod
    def analyze(self, content: bytes, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyzes file content and returns findings."""
        pass
