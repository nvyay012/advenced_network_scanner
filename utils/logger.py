import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
import json
from datetime import datetime

class CustomJsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'thread': record.threadName,
        }
        
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
            
        return json.dumps(log_entry)

def setup_logger(level=logging.INFO, log_dir='logs', json_format=False):
    """Configure logging for the application"""
    # Create logs directory if it doesn't exist
    log_dir = Path(log_dir)
    log_dir.mkdir(exist_ok=True)
    
    # Create formatters
    if json_format:
        file_formatter = CustomJsonFormatter()
    else:
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # Setup rotating file handler
    file_handler = RotatingFileHandler(
        log_dir / 'scanner.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Setup console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(console_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Remove any existing handlers
    root_logger.handlers = []
    
    # Add handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Setup error file handler
    error_handler = RotatingFileHandler(
        log_dir / 'error.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    root_logger.addHandler(error_handler)
    
    # Suppress some verbose loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('charset_normalizer').setLevel(logging.WARNING)
    
    return root_logger