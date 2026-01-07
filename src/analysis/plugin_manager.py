import os
import importlib.util
import logging
from typing import List
from .analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

class PluginManager:
    """Loads and manages analysis plugins."""
    
    def __init__(self, plugin_dir: str):
        self.plugin_dir = plugin_dir
        self.plugins: List[BaseAnalyzer] = []

    def load_plugins(self):
        """Discovers and instantiates plugins from the plugin directory."""
        if not os.path.exists(self.plugin_dir):
            return

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and filename != "__init__.py":
                file_path = os.path.join(self.plugin_dir, filename)
                module_name = filename[:-3]
                
                try:
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Look for classes that inherit from BaseAnalyzer
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            issubclass(attr, BaseAnalyzer) and 
                            attr is not BaseAnalyzer):
                            self.plugins.append(attr())
                            logger.info(f"Loaded plugin: {attr().name}")
                except Exception as e:
                    logger.error(f"Failed to load plugin {filename}: {e}")
