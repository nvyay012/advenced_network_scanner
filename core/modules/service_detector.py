import socket
import logging
import re
from concurrent.futures import ThreadPoolExecutor

class ServiceDetector:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.timeout = config.get('timeout', 2)
        self.max_workers = config.get('max_workers', 10)
        
        # Common service signatures
        self.signatures = {
            'ssh': rb'SSH-\d\.\d',
            'http': rb'HTTP/\d\.\d',
            'ftp': rb'220.*FTP',
            'smtp': rb'220.*SMTP',
            'mysql': rb'.\x00\x00\x00\x0a\d+\.\d+\.\d+',
            'redis': rb'\+PONG',
        }

    def detect_service(self, target, port):
        """Detect service running on a specific port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                
                # Send probes for different protocols
                probes = [
                    b"HEAD / HTTP/1.0\r\n\r\n",
                    b"SSH-2.0-OpenSSH_8.2p1\r\n",
                    b"HELP\r\n",
                    b"PING\r\n",
                ]
                
                for probe in probes:
                    try:
                        sock.send(probe)
                        response = sock.recv(1024)
                        
                        # Check response against signatures
                        for service, pattern in self.signatures.items():
                            if re.search(pattern, response):
                                return {
                                    'port': port,
                                    'service': service,
                                    'banner': response[:100].decode('utf-8', 'ignore')
                                }
                    except socket.error:
                        continue
                
                # If no specific service detected, return unknown
                return {
                    'port': port,
                    'service': 'unknown',
                    'banner': ''
                }
                
        except socket.error as e:
            self.logger.debug(f"Error detecting service on port {port}: {str(e)}")
            return None

    def detect(self, target, open_ports):
        """Detect services on all open ports"""
        self.logger.info(f"Starting service detection on {len(open_ports)} ports")
        services = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.detect_service, target, port): port 
                for port in open_ports
            }
            
            for future in future_to_port:
                try:
                    if result := future.result():
                        services.append(result)
                except Exception as e:
                    self.logger.error(f"Service detection failed: {str(e)}")
        
        return services