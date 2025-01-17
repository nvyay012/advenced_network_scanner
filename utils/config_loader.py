import yaml
import logging
from pathlib import Path

class ConfigLoader:
    def __init__(self, config_path):
        self.logger = logging.getLogger(__name__)
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_path) as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            raise

    def get_scan_config(self, scan_type):
        """Get configuration for specific scan type"""
        base_config = self.config.get('default', {})
        scan_config = self.config.get(scan_type, {})
        return {**base_config, **scan_config}