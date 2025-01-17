import json
import csv
from pathlib import Path
from datetime import datetime
import logging
import xml.etree.ElementTree as ET
from xml.dom import minidom

class ReportGenerator:
    def __init__(self, scan_results, scan_metadata):
        self.results = scan_results
        self.metadata = scan_metadata
        self.logger = logging.getLogger(__name__)

    def generate_reports(self, output_dir):
        """Generate scan reports in multiple formats"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = f"scan_report_{timestamp}"

        # Generate reports in different formats
        self._generate_json_report(output_dir / f"{base_name}.json")
        self._generate_text_report(output_dir / f"{base_name}.txt")
        self._generate_csv_report(output_dir / f"{base_name}.csv")
        self._generate_xml_report(output_dir / f"{base_name}.xml")
        self._generate_html_report(output_dir / f"{base_name}.html")

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
            
            if 'os_info' in self.results:
                f.write(f"Operating System Information:\n")
                for key, value in self.results['os_info'].items():
                    f.write(f"- {key}: {value}\n")
                f.write("\n")
            
            if 'vulnerabilities' in self.results:
                f.write(f"Potential Vulnerabilities:\n")
                for vuln in self.results['vulnerabilities']:
                    f.write(f"- {vuln['type']}: {vuln['vulnerability']}\n")
                    f.write(f"  Details: {vuln['details']}\n")

    def _generate_csv_report(self, filepath):
        """Generate CSV report of findings"""
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Category', 'Port', 'Service', 'Details'])
            
            # Write open ports
            for port in self.results.get('ports', []):
                writer.writerow(['Port', port, '', ''])
            
            # Write services
            for service in self.results.get('services', []):
                writer.writerow(['Service', service['port'], service['service'], service['banner']])
            
            # Write vulnerabilities
            for vuln in self.results.get('vulnerabilities', []):
                writer.writerow(['Vulnerability', vuln.get('port', ''), vuln['type'], vuln['details']])

    def _generate_xml_report(self, filepath):
        """Generate XML report"""
        root = ET.Element("scan_report")
        
        # Add metadata
        metadata = ET.SubElement(root, "metadata")
        for key, value in self.metadata.items():
            ET.SubElement(metadata, key).text = str(value)
        
        # Add results
        results = ET.SubElement(root, "results")
        
        # Add ports
        ports = ET.SubElement(results, "ports")
        for port in self.results.get('ports', []):
            ET.SubElement(ports, "port").text = str(port)
        
        # Add services
        services = ET.SubElement(results, "services")
        for service in self.results.get('services', []):
            service_elem = ET.SubElement(services, "service")
            for key, value in service.items():
                ET.SubElement(service_elem, key).text = str(value)
        
        # Add vulnerabilities
        vulns = ET.SubElement(results, "vulnerabilities")
        for vuln in self.results.get('vulnerabilities', []):
            vuln_elem = ET.SubElement(vulns, "vulnerability")
            for key, value in vuln.items():
                ET.SubElement(vuln_elem, key).text = str(value)
        
        # Write to file with pretty printing
        xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="    ")
        with open(filepath, 'w') as f:
            f.write(xml_str)

    def _generate_html_report(self, filepath):
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #2c3e50; }}
                .section {{ margin: 20px 0; padding: 10px; background-color: #f8f9fa; }}
                .vulnerability {{ color: #dc3545; }}
            </style>
        </head>
        <body>
            <h1>Network Security Scan Report</h1>
            
            <div class="section">
                <h2>Scan Details</h2>
                <p>Target: {self.metadata['target']}</p>
                <p>Scan Type: {self.metadata['scan_type']}</p>
                <p>Timestamp: {self.metadata['timestamp']}</p>
            </div>
        """
        
        # Add open ports
        if 'ports' in self.results:
            html += """
            <div class="section">
                <h2>Open Ports</h2>
                <ul>
            """
            for port in self.results['ports']:
                html += f"<li>Port {port}</li>"
            html += "</ul></div>"
        
        # Add services
        if 'services' in self.results:
            html += """
            <div class="section">
                <h2>Detected Services</h2>
                <ul>
            """
            for service in self.results['services']:
                html += f"<li>Port {service['port']}: {service['service']} - {service['banner']}</li>"
            html += "</ul></div>"
        
        # Add vulnerabilities
        if 'vulnerabilities' in self.results:
            html += """
            <div class="section">
                <h2>Potential Vulnerabilities</h2>
                <ul>
            """
            for vuln in self.results['vulnerabilities']:
                html += f"""
                <li class="vulnerability">
                    <strong>{vuln['type']}</strong>: {vuln['vulnerability']}<br>
                    Details: {vuln['details']}
                </li>
                """
            html += "</ul></div>"
        
        html += """
        </body>
        </html>
        """
        
        with open(filepath, 'w') as f:
            f.write(html)

    def export_to_database(self, db_connection):
        """Export results to a database"""
        try:
            cursor = db_connection.cursor()
            
            # Create tables if they don't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    scan_type TEXT,
                    timestamp TEXT
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    type TEXT,
                    port INTEGER,
                    description TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (id)
                )
            """)
            
            # Insert scan metadata
            cursor.execute("""
                INSERT INTO scans (target, scan_type, timestamp)
                VALUES (?, ?, ?)
            """, (
                self.metadata['target'],
                self.metadata['scan_type'],
                self.metadata['timestamp']
            ))
            
            scan_id = cursor.lastrowid
            
            # Insert findings
            for port in self.results.get('ports', []):
                cursor.execute("""
                    INSERT INTO findings (scan_id, type, port, description)
                    VALUES (?, ?, ?, ?)
                """, (scan_id, 'open_port', port, f"Port {port} is open"))
            
            for vuln in self.results.get('vulnerabilities', []):
                cursor.execute("""
                    INSERT INTO findings (scan_id, type, port, description)
                    VALUES (?, ?, ?, ?)
                """, (
                    scan_id,
                    'vulnerability',
                    vuln.get('port', 0),
                    f"{vuln['type']}: {vuln['details']}"
                ))
            
            db_connection.commit()
            self.logger.info("Results exported to database successfully")
            
        except Exception as e:
            self.logger.error(f"Database export failed: {str(e)}")
            db_connection.rollback()
            raise