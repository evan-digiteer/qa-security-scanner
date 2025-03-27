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

def clear_zap_session(zap):
    """Clear the ZAP session to ensure a fresh scan."""
    try:
        logger.info("Clearing ZAP session before starting new scan")
        zap.core.new_session()
        logger.info("ZAP session cleared successfully")
        return True
    except Exception as e:
        logger.error(f"Error clearing ZAP session: {str(e)}")
        return False

def get_last_zap_messages(zap, count=10):
    """Get the last messages from ZAP for debugging purposes."""
    try:
        messages = zap.core.messages()
        if messages and len(messages) > 0:
            recent_messages = messages[-count:] if len(messages) >= count else messages
            return recent_messages
        return []
    except Exception as e:
        logger.error(f"Error getting ZAP messages: {str(e)}")
        return []

def log_zap_messages(zap, count=10):
    """Log the last ZAP messages for debugging."""
    logger.info(f"Retrieving last {count} ZAP messages for debugging:")
    messages = get_last_zap_messages(zap, count)
    
    if not messages:
        logger.info("No ZAP messages found")
        return
    
    for i, msg in enumerate(messages):
        try:
            logger.info(f"Message {i+1}: {msg.get('requestHeader', '').splitlines()[0]} - {msg.get('responseHeader', '').splitlines()[0]}")
        except (IndexError, AttributeError, KeyError):
            logger.info(f"Message {i+1}: Unable to parse message format")

def access_url(zap, target_url):
    """Make sure ZAP can access the target URL before scanning."""
    try:
        logger.info(f"Accessing target URL via ZAP: {target_url}")
        # Use the core.access_url method instead of urlopen (which might not exist in all versions)
        zap.core.access_url(url=target_url)
        logger.info("Successfully accessed target URL")
        
        # Wait a moment for ZAP to process the page
        time.sleep(2)
        return True
    except Exception as e:
        logger.error(f"Error accessing target URL via ZAP: {str(e)}")
        # Try an alternative method if the first fails
        try:
            logger.info("Attempting alternative method to access URL...")
            resp = requests.get(target_url, proxies={'http': os.getenv("ZAP_API_URL"), 'https': os.getenv("ZAP_API_URL")})
            logger.info(f"Alternative access successful. Status code: {resp.status_code}")
            time.sleep(2)
            return True
        except Exception as inner_e:
            logger.error(f"Alternative access also failed: {str(inner_e)}")
            return False

def retry_scan(scan_func, max_retries=3, wait_time=5, *args, **kwargs):
    """Generic retry function for scans."""
    attempt = 0
    while attempt < max_retries:
        attempt += 1
        logger.info(f"Scan attempt {attempt} of {max_retries}")
        
        scan_id = scan_func(*args, **kwargs)
        
        if scan_id and scan_id != '0':
            logger.info(f"Scan attempt {attempt} successful, got scan_id: {scan_id}")
            return scan_id
        
        if attempt < max_retries:
            logger.warning(f"Scan attempt {attempt} failed. Waiting {wait_time} seconds before retrying...")
            time.sleep(wait_time)
            # Increase wait time for next retry
            wait_time = min(wait_time * 2, 30)  # Cap at 30 seconds
    
    logger.error(f"All {max_retries} scan attempts failed")
    return None

def run_spider_scan(zap, target_url):
    """Run the spider scan against the target."""
    logger.info(f"Starting Spider scan for {target_url}")
    
    try:
        # First, make sure the target is in the sites tree
        logger.info("Checking sites tree")
        sites = zap.core.sites
        logger.debug(f"Sites in tree: {sites}")
        
        if not any(target_url.startswith(site) for site in sites):
            logger.info("Target not in sites tree, accessing it first")
            if not access_url(zap, target_url):
                logger.error("Target URL couldn't be accessed through ZAP")
                return False
        
        # Enhanced retry mechanism for spider scan
        def start_spider_scan():
            try:
                return zap.spider.scan(url=target_url)
            except Exception as e:
                logger.error(f"Error starting spider scan: {str(e)}")
                return None
        
        scan_id = retry_scan(start_spider_scan, max_retries=3, wait_time=5)
        
        if not scan_id:
            # Last resort - try with different parameter styles
            logger.info("Trying alternative spider scan approaches...")
            
            # Try direct URL parameter
            try:
                scan_id = zap.spider.scan(target_url)
                if scan_id and scan_id != '0':
                    logger.info(f"Direct URL parameter approach successful, got scan_id: {scan_id}")
                else:
                    logger.error("Direct URL parameter approach failed")
                    log_zap_messages(zap)
                    return False
            except Exception as e:
                logger.error(f"Exception during alternative spider scan: {str(e)}")
                log_zap_messages(zap)
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
        
        # Verify spider found URLs
        urls = zap.spider.results(scan_id)
        if not urls or len(urls) == 0:
            logger.warning("Spider completed but found no URLs")
        else:
            logger.info(f"Spider found {len(urls)} URL(s)")
            for i, u in enumerate(urls[:5]):  # Log first 5 URLs for debugging
                logger.debug(f"URL {i+1}: {u}")
        
        logger.info("Spider scan completed")
        return True
    except Exception as e:
        logger.error(f"Error during spider scan: {str(e)}")
        # Add additional debugging information
        logger.error(f"Exception type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        # Log ZAP messages to help debug
        log_zap_messages(zap)
        return False

def run_active_scan(zap, target_url):
    """Run the active scan against the target."""
    logger.info(f"Starting Active scan for {target_url}")
    
    try:
        # Try to include the target in context for better scanning
        try:
            zap.context.new_context("Target Context")
            zap.context.include_in_context("Target Context", "\\Q" + target_url + "\\E.*")
            logger.info("Created and configured target context")
            
            # Add delay to ensure context is fully registered before starting scan
            logger.info("Waiting 2 seconds for context to be fully registered...")
            time.sleep(2)
        except Exception as ce:
            logger.warning(f"Could not create context: {str(ce)}")
        
        # Enhanced retry mechanism for active scan
        def start_active_scan():
            try:
                return zap.ascan.scan(url=target_url)
            except Exception as e:
                logger.error(f"Error starting active scan: {str(e)}")
                return None
        
        scan_id = retry_scan(start_active_scan, max_retries=3, wait_time=8)
        
        if not scan_id:
            # Last resort - try with different parameter styles
            logger.info("Trying alternative active scan approaches...")
            
            # Try direct URL parameter
            try:
                scan_id = zap.ascan.scan(target_url)
                if scan_id and scan_id != '0':
                    logger.info(f"Direct URL parameter approach successful, got scan_id: {scan_id}")
                else:
                    # Try with recurse parameter
                    scan_id = zap.ascan.scan(url=target_url, recurse=True)
                    if scan_id and scan_id != '0':
                        logger.info(f"Recurse parameter approach successful, got scan_id: {scan_id}")
                    else:
                        logger.error("All active scan approaches failed")
                        logger.info("Logging last 10 ZAP messages for debugging:")
                        log_zap_messages(zap)
                        return False
            except Exception as e:
                logger.error(f"Exception during alternative active scan: {str(e)}")
                log_zap_messages(zap)
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
                log_zap_messages(zap)
                return False
        
        # Get scan statistics
        try:
            alerts = zap.core.alerts()
            logger.info(f"Active scan completed with {len(alerts)} alert(s)")
            
            # Summarize alerts by risk level for better reporting
            risk_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
            for alert in alerts:
                if "risk" in alert:
                    risk = alert["risk"]
                    if risk in risk_counts:
                        risk_counts[risk] += 1
                    
            logger.info(f"Alert summary by risk: {risk_counts}")
            
        except Exception as ae:
            logger.warning(f"Could not retrieve alerts: {str(ae)}")
        
        return True
    except Exception as e:
        logger.error(f"Error during active scan: {str(e)}")
        # Add additional debugging information
        logger.error(f"Exception type: {type(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        # Log ZAP messages to help debug
        log_zap_messages(zap)
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
        # Try alternative approach
        try:
            logger.info("Attempting alternative report generation")
            report = zap.core.jsonreport()
            json_report_file = REPORTS_DIR / f"zap_report_{timestamp}.json"
            with open(json_report_file, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"JSON report saved to {json_report_file}")
            return json_report_file
        except Exception as je:
            logger.error(f"Alternative report generation also failed: {str(je)}")
            return None

def shutdown_zap(zap):
    """Shut down the ZAP instance."""
    try:
        logger.info("Shutting down ZAP instance...")
        zap.core.shutdown()
        logger.info("ZAP shutdown successfully initiated")
        print("ZAP session closed successfully.")
        return True
    except Exception as e:
        logger.error(f"Error shutting down ZAP: {str(e)}")
        return False

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="OWASP ZAP Security Scanner")
    parser.add_argument("--target", "-t", help="Target URL to scan")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    
    # Set debug level if requested
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
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
    
    # Display ZAPv2 version for debugging
    logger.debug(f"Python OWASP ZAP library version: {ZAPv2.__version__ if hasattr(ZAPv2, '__version__') else 'unknown'}")
    
    # Check if ZAP is running before proceeding
    try:
        # Test connection by making a simple request to the ZAP API
        response = requests.get(f"{zap_api_url}/JSON/core/view/version/", 
                              params={'apikey': zap_api_key},
                              timeout=10)
        
        if response.status_code != 200:
            logger.error(f"Failed to connect to ZAP API. Status code: {response.status_code}")
            logger.error(f"Response body: {response.text}")
            sys.exit(1)
            
        # Display ZAP version
        zap_version = response.json().get('version', 'unknown')
        logger.info(f"Successfully connected to ZAP API (version {zap_version})")
        
        # Initialize ZAP connection - ensure both http and https use the same proxy
        proxies = {'http': zap_api_url, 'https': zap_api_url}
        zap = ZAPv2(apikey=zap_api_key, proxies=proxies)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to ZAP API: {str(e)}")
        logger.error("Ensure ZAP is running and the API URL is correct")
        sys.exit(1)
    
    try:
        # Clear the ZAP session before starting a new scan
        session_cleared = clear_zap_session(zap)
        if not session_cleared:
            logger.warning("Failed to clear ZAP session. Proceeding with current session.")
        
        # Run the scans
        logger.info(f"Starting security scan for {target_url}")
        
        # Verify access to target URL first
        if not access_url(zap, target_url):
            logger.error("Failed to access target URL. Please check if the URL is accessible and try again.")
            sys.exit(1)
        
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
        
        # Shutdown ZAP after scan completion
        shutdown_zap(zap)
        
    except Exception as e:
        logger.error(f"Error during scanning: {str(e)}")
        # Additional debugging information for the main try-except block
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        
        # Attempt to shutdown ZAP even if scan fails
        try:
            shutdown_zap(zap)
        except:
            logger.error("Could not shutdown ZAP instance after error")
            
        sys.exit(1)

if __name__ == "__main__":
    main()
