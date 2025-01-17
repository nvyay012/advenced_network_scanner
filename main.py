/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   main.py                                            :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: hbarda <hbarda@student.42.fr>              #+#  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2025-01-17 10:11:04 by hbarda            #+#    #+#             */
/*   Updated: 2025-01-17 10:11:04 by hbarda           ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */


import argparse
import sys
import logging
from datetime import datetime
from pathlib import Path
from core.scanner import NetworkScanner
from core.report_generator import ReportGenerator
from utils.config_loader import ConfigLoader
from utils.logger import setup_logger

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Security Scanner')
    parser.add_argument('target', help='Target host or network (CIDR notation)')
    parser.add_argument('-c', '--config', default='config.yaml', help='Path to config file')
    parser.add_argument('-o', '--output', help='Output directory for reports')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--scan-type', choices=['quick', 'full', 'stealth'], default='quick',
                       help='Type of scan to perform')
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(log_level)
    logger = logging.getLogger(__name__)

    try:
        # Load configuration
        config = ConfigLoader(args.config)
        scan_config = config.get_scan_config(args.scan_type)

        # Initialize scanner
        scanner = NetworkScanner(
            target=args.target,
            config=scan_config,
            scan_type=args.scan_type
        )

        # Run scan
        logger.info(f"Starting {args.scan_type} scan of {args.target}")
        start_time = datetime.now()
        results = scanner.run()
        
        # Generate report
        if args.output:
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
            report_gen = ReportGenerator(results, scanner.get_scan_metadata())
            report_gen.generate_reports(output_dir)

        logger.info(f"Scan completed in {datetime.now() - start_time}")

    except KeyboardInterrupt:
        logger.error("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        if args.verbose:
            logger.exception("Detailed error information:")
        sys.exit(1)

if __name__ == "__main__":
    main()