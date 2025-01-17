# Advanced Network Security Scanner

A comprehensive network security scanning tool with multiple modules for port scanning, 
service detection, OS fingerprinting, and vulnerability assessment.

## Setup
1. Create a virtual environment: `python -m venv venv`
2. Activate the virtual environment:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`
3. Install requirements: `pip install -r requirements.txt`

## Usage
Basic scan: `python main.py example.com`
Full scan: `python main.py example.com --scan-type full`
