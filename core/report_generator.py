import json
from pathlib import Path
from datetime import datetime
import logging

class ReportGenerator:
    def __init__(self, scan_results, scan_metadata):
        self.results = scan_results
        self.metadata = scan_metadata
        self.logger = logging.getLogger(__name__)

    def generate_reports(self, output_dir):
        """Generate scan reports in multiple formats"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"scan_report_{timestamp}"

        # Generate JSON report
        self._generate_json_report(output_dir / f"{base_name}.json")

        # Generate human-readable report
        self._generate_text_report(output_dir / f"{base_name}.txt")

        self.logger.info(f"Reports generated in {output_dir}")

    def _generate_json_report(self, filepath):
        """Generate detailed JSON report"""
        report_data = {
            'metadata': self.metadata,
            'results': self.results
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)

    def _generate_text_report(self, filepath):
        """Generate human-readable text report"""
        with open(filepath, 'w') as f:
            f.write(f"Network Security Scan Report\n")
            f.write(f"{'='* 50}\n\n")
            
            # Write metadata
            f.write(f"Scan Details:\n")
            f.write(f"Target: {self.metadata['target']}\n")
            f.write(f"Scan Type: {self.metadata['scan_type']}\n")
            f.write(f"Timestamp: {self.metadata['timestamp']}\n\n")
            
            # Write results sections
            if 'ports' in self.results:
                f.write(f"Open Ports:\n")
                for port in self.results['ports']:
                    f.write(f"- {port}\n")
                f.write("\n")
            
            if 'services' in self.results:
                f.write(f"Detected Services:\n")
                for service in self.results['services']:
                    f.write(f"- {service}\n")
                f.write("\n")
            
            if 'vulnerabilities' in self.results:
                f.write(f"Potential Vulnerabilities:\n")
                for vuln in self.results['vulnerabilities']:
                    f.write(f"- {vuln}\n")