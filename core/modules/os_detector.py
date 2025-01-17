import logging
import re
import socket
import struct

class OSDetector:
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.timeout = config.get('timeout', 2)

    def detect(self, target):
        """Detect operating system of the target"""
        try:
            os_info = {
                'os_name': None,
                'os_version': None,
                'confidence': 0
            }
            
            # Try multiple detection methods
            methods = [
                self._detect_by_ttl,
                self._detect_by_tcp_window,
                self._detect_by_banner
            ]
            
            for method in methods:
                try:
                    result = method(target)
                    if result and result['confidence'] > os_info['confidence']:
                        os_info.update(result)
                except Exception as e:
                    self.logger.debug(f"OS detection method failed: {str(e)}")
            
            return os_info if os_info['os_name'] else None
            
        except Exception as e:
            self.logger.error(f"OS detection failed: {str(e)}")
            return None

    def _detect_by_ttl(self, target):
        """Detect OS by analyzing TTL values"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
                sock.settimeout(self.timeout)
                sock.connect((target, 0))
                ttl = struct.unpack('B', sock.getsockopt(socket.SOL_IP, socket.IP_TTL, 1))[0]
                
                # TTL fingerprinting
                if ttl <= 64:
                    return {'os_name': 'Linux', 'confidence': 60}
                elif ttl <= 128:
                    return {'os_name': 'Windows', 'confidence': 60}
                elif ttl <= 255:
                    return {'os_name': 'Cisco/Network', 'confidence': 50}
        except:
            return None

    def _detect_by_tcp_window(self, target):
        """Detect OS by TCP window size"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((target, 80))
                window_size = sock.getsockopt(socket.SOL_TCP, socket.TCP_MAXSEG)
                
                if window_size == 65535:
                    return {'os_name': 'Windows', 'confidence': 70}
                elif window_size == 5840:
                    return {'os_name': 'Linux', 'confidence': 70}
        except:
            return None

    def _detect_by_banner(self, target):
        """Detect OS from service banners"""
        common_ports = [22, 80, 443]
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect((target, port))
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    response = sock.recv(1024).decode('utf-8', 'ignore')
                    
                    # Look for OS indicators in response
                    if 'Ubuntu' in response or 'Debian' in response:
                        return {
                            'os_name': 'Linux',
                            'os_version': re.search(r'Ubuntu/(\d+\.\d+)', response),
                            'confidence': 80
                        }
                    elif 'Win' in response:
                        return {
                            'os_name': 'Windows',
                            'os_version': re.search(r'Win(\d+)', response),
                            'confidence': 80
                        }
            except:
                continue
        
        return None