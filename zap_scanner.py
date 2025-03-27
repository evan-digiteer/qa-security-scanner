#!/usr/bin/env python3

import os
import sys
import time
import logging
import argparse
import urllib.parse
from datetime import datetime
from pathlib import Path

import dotenv
from zapv2 import ZAPv2

# Load environment variables
dotenv.load_dotenv()

# Setup directories
BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"

# Create directories if they don't exist
LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# Configure logging
def setup_logging():
    log_file = LOGS_DIR / "zap_scanner.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger("zap_scanner")

logger = setup_logging()

def validate_url(url):
    """Validate if the provided string is a proper URL."""
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_timestamp():
    """Get current timestamp in YYYYMMDD_HHMMSS format."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def run_spider_scan(zap, target_url):
    """Run the spider scan against the target."""
    logger.info(f"Starting Spider scan for {target_url}")
    
    # Start the spider scan
    scan_id = zap.spider.scan(target_url)
    
    # Wait for the spider scan to complete
    while True:
        status = int(zap.spider.status(scan_id))
        logger.info(f"Spider scan progress: {status}%")
        if status >= 100:
            break
        time.sleep(5)
    
    logger.info("Spider scan completed")

def run_active_scan(zap, target_url):
    """Run the active scan against the target."""
    logger.info(f"Starting Active scan for {target_url}")
    
    # Start the active scan
    scan_id = zap.ascan.scan(target_url)
    
    # Wait for the active scan to complete
    while True:
        status = int(zap.ascan.status(scan_id))
        logger.info(f"Active scan progress: {status}%")
        if status >= 100:
            break
        time.sleep(5)
    
    logger.info("Active scan completed")

def generate_report(zap):
    """Generate an HTML report of the scan results."""
    logger.info("Generating report")
    
    timestamp = get_timestamp()
    report_file = REPORTS_DIR / f"zap_report_{timestamp}.html"
    
    # Generate the report
    report = zap.core.htmlreport()
    
    # Save the report to a file
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    logger.info(f"Report saved to {report_file}")
    return report_file

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="OWASP ZAP Security Scanner")
    parser.add_argument("--target", "-t", help="Target URL to scan")
    args = parser.parse_args()
    
    # Get target URL from args or environment
    target_url = args.target or os.getenv("DEFAULT_TARGET_URL")
    
    # Validate the URL
    if not validate_url(target_url):
        logger.error(f"Invalid target URL: {target_url}")
        sys.exit(1)
    
    # Connect to ZAP
    zap_api_url = os.getenv("ZAP_API_URL")
    zap_api_key = os.getenv("ZAP_API_KEY", "")
    
    logger.info(f"Connecting to ZAP API at {zap_api_url}")
    zap = ZAPv2(apikey=zap_api_key, proxies={'http': zap_api_url, 'https': zap_api_url})
    
    try:
        # Run the scans
        logger.info(f"Starting security scan for {target_url}")
        
        # Spider scan
        run_spider_scan(zap, target_url)
        
        # Active scan
        run_active_scan(zap, target_url)
        
        # Generate report
        report_file = generate_report(zap)
        
        logger.info("Security scan completed successfully")
        print(f"\nScan completed! Report saved to: {report_file}")
        
    except Exception as e:
        logger.error(f"Error during scanning: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
