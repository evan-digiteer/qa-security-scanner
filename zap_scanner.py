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
import requests

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
    
    try:
        # Start the spider scan
        scan_id = zap.spider.scan(target_url)
        
        # Verify scan_id is valid
        if not scan_id or scan_id == '0':
            logger.error("Failed to get valid scan_id for spider scan")
            return False
        
        # Wait for the spider scan to complete with exponential backoff
        wait_time = 1  # Start with 1 second
        max_wait_time = 20  # Maximum wait time between checks
        
        while True:
            try:
                status = int(zap.spider.status(scan_id))
                logger.info(f"Spider scan progress: {status}%")
                if status >= 100:
                    break
                
                # Exponential backoff with maximum limit
                wait_time = min(wait_time * 1.5, max_wait_time)
                time.sleep(wait_time)
            except Exception as e:
                logger.error(f"Error checking spider scan status: {str(e)}")
                return False
        
        logger.info("Spider scan completed")
        return True
    except Exception as e:
        logger.error(f"Error during spider scan: {str(e)}")
        return False

def run_active_scan(zap, target_url):
    """Run the active scan against the target."""
    logger.info(f"Starting Active scan for {target_url}")
    
    try:
        # Start the active scan
        scan_id = zap.ascan.scan(target_url)
        
        # Verify scan_id is valid
        if not scan_id or scan_id == '0':
            logger.error("Failed to get valid scan_id for active scan")
            return False
        
        # Wait for the active scan to complete with exponential backoff
        wait_time = 1  # Start with 1 second
        max_wait_time = 30  # Maximum wait time between checks (active scans take longer)
        
        while True:
            try:
                status = int(zap.ascan.status(scan_id))
                logger.info(f"Active scan progress: {status}%")
                if status >= 100:
                    break
                
                # Exponential backoff with maximum limit
                wait_time = min(wait_time * 1.5, max_wait_time)
                time.sleep(wait_time)
            except Exception as e:
                logger.error(f"Error checking active scan status: {str(e)}")
                return False
        
        logger.info("Active scan completed")
        return True
    except Exception as e:
        logger.error(f"Error during active scan: {str(e)}")
        return False

def generate_report(zap):
    """Generate an HTML report of the scan results."""
    logger.info("Generating report")
    
    timestamp = get_timestamp()
    report_file = REPORTS_DIR / f"zap_report_{timestamp}.html"
    
    try:
        # Generate the report
        report = zap.core.htmlreport()
        
        # Save the report to a file
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        logger.info(f"Report saved to {report_file}")
        return report_file
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return None

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
    
    # Check if ZAP is running before proceeding
    try:
        # Test connection by making a simple request to the ZAP API
        response = requests.get(f"{zap_api_url}/JSON/core/view/version/", 
                              params={'apikey': zap_api_key},
                              timeout=10)
        
        if response.status_code != 200:
            logger.error(f"Failed to connect to ZAP API. Status code: {response.status_code}")
            sys.exit(1)
            
        logger.info("Successfully connected to ZAP API")
        
        # Initialize ZAP connection
        zap = ZAPv2(apikey=zap_api_key, proxies={'http': zap_api_url, 'https': zap_api_url})
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to ZAP API: {str(e)}")
        logger.error("Ensure ZAP is running and the API URL is correct")
        sys.exit(1)
    
    try:
        # Run the scans
        logger.info(f"Starting security scan for {target_url}")
        
        # Spider scan
        spider_success = run_spider_scan(zap, target_url)
        if not spider_success:
            logger.warning("Spider scan had issues. Continuing with active scan anyway.")
        
        # Active scan
        active_success = run_active_scan(zap, target_url)
        if not active_success:
            logger.error("Active scan failed.")
            sys.exit(1)
        
        # Generate report
        report_file = generate_report(zap)
        if not report_file:
            logger.error("Failed to generate report.")
            sys.exit(1)
        
        logger.info("Security scan completed successfully")
        print(f"\nScan completed! Report saved to: {report_file}")
        
    except Exception as e:
        logger.error(f"Error during scanning: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
