import yaml
import logging
from pathlib import Path

class ConfigLoader:
    def __init__(self, config_path):
        self.logger = logging.getLogger(__name__)
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.validate_config()

    def _load_config(self):
        """Load configuration from YAML file"""
        try:
            with open(self.config_path) as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to load config: {str(e)}")
            raise

    def validate_config(self):
        """Validate configuration structure and values"""
        required_sections = ['default', 'quick', 'full', 'stealth']
        required_params = ['timeout', 'threads', 'port_range']
        
        # Check for required sections
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required config section: {section}")
        
        # Check for required parameters in each section
        for section in required_sections:
            section_config = self.config[section]
            for param in required_params:
                if param not in section_config:
                    raise ValueError(f"Missing required parameter '{param}' in section '{section}'")
            
            # Validate specific parameters
            if not isinstance(section_config['threads'], int):
                raise ValueError(f"'threads' must be an integer in section '{section}'")
            if not isinstance(section_config['timeout'], (int, float)):
                raise ValueError(f"'timeout' must be a number in section '{section}'")
            if not isinstance(section_config['port_range'], list):
                raise ValueError(f"'port_range' must be a list in section '{section}'")

    def get_scan_config(self, scan_type):
        """Get configuration for specific scan type"""
        if scan_type not in self.config:
            self.logger.warning(f"Unknown scan type: {scan_type}, using default")
            scan_type = 'default'
        
        # Merge with default config
        base_config = self.config.get('default', {})
        scan_config = self.config.get(scan_type, {})
        
        # Deep merge configurations
        merged_config = self._deep_merge(base_config, scan_config)
        self.logger.debug(f"Loaded configuration for {scan_type} scan")
        
        return merged_config

    def _deep_merge(self, dict1, dict2):
        """Deep merge two dictionaries"""
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def reload_config(self):
        """Reload configuration from file"""
        self.logger.info("Reloading configuration")
        self.config = self._load_config()
        self.validate_config()
        return self.config