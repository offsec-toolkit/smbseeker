import pytest
import os
import shutil
from src.analysis.plugin_manager import PluginManager

@pytest.fixture
def plugin_dir(tmp_path):
    d = tmp_path / "plugins"
    d.mkdir()
    return str(d)

def test_plugin_manager_loading(plugin_dir):
    # Create a mock plugin file
    plugin_content = """
from src.analysis.analyzer import BaseAnalyzer
class MockPlugin(BaseAnalyzer):
    @property
    def name(self): return "mock_plugin"
    def analyze(self, c, m): return [{"type": "mock"}]
"""
    with open(os.path.join(plugin_dir, "mock_plugin.py"), "w") as f:
        f.write(plugin_content)
        
    manager = PluginManager(plugin_dir)
    manager.load_plugins()
    
    assert len(manager.plugins) == 1
    assert manager.plugins[0].name == "mock_plugin"
