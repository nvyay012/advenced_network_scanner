/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   scanner.py                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hbarda <hbarda@student.42.fr>              #+#  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025-01-17 10:12:18 by hbarda            #+#    #+#             */
/*   Updated: 2025-01-17 10:12:18 by hbarda           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

import logging
import socket
import threading
from queue import Queue
from datetime import datetime
from .modules.port_scanner import PortScanner
from .modules.service_detector import ServiceDetector
from .modules.vulnerability_scanner import VulnerabilityScanner
from .modules.os_detector import OSDetector

class NetworkScanner:
    def __init__(self, target, config, scan_type='quick'):
        self.target = target
        self.config = config
        self.scan_type = scan_type
        self.logger = logging.getLogger(__name__)
        self.results = {}
        
        # Initialize scan modules
        self.port_scanner = PortScanner(config.get('port_scan', {}))
        self.service_detector = ServiceDetector(config.get('service_detection', {}))
        self.vuln_scanner = VulnerabilityScanner(config.get('vulnerability_scan', {}))
        self.os_detector = OSDetector(config.get('os_detection', {}))

    def run(self):
        """Execute the network scan"""
        try:
            self.logger.info(f"Initializing {self.scan_type} scan...")
            
            # Phase 1: Port Scanning
            open_ports = self.port_scanner.scan(self.target)
            self.results['ports'] = open_ports
            
            # Phase 2: Service Detection
            if open_ports:
                services = self.service_detector.detect(self.target, open_ports)
                self.results['services'] = services
            
            # Phase 3: OS Detection
            os_info = self.os_detector.detect(self.target)
            self.results['os_info'] = os_info
            
            # Phase 4: Vulnerability Scanning (if enabled)
            if self.config.get('enable_vuln_scan', False):
                vulns = self.vuln_scanner.scan(
                    self.target,
                    self.results['services'],
                    self.results['os_info']
                )
                self.results['vulnerabilities'] = vulns
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise

    def get_scan_metadata(self):
        """Return metadata about the scan"""
        return {
            'target': self.target,
            'scan_type': self.scan_type,
            'timestamp': datetime.now().isoformat(),
            'config': self.config
        }
