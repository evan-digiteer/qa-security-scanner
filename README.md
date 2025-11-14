# Security Scanner

A Python-based automated security scanner using OWASP ZAP (Zed Attack Proxy).

## Features

- Automated Spider and Active scanning
- Configurable via environment variables
- Command-line interface
- Structured logging
- HTML report generation

## Prerequisites

1. Python 3.6 or higher
2. OWASP ZAP installed locally

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/qa-security-scanner.git
   cd qa-security-scanner
   ```

2. Install the dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Configure your environment:
   ```
   cp .env.example .env
   ```
   Then edit the `.env` file with your specific configuration values.

## Usage

### Running ZAP

OWASP ZAP can be run in two modes:

1. **GUI Mode** - With the full user interface, useful for interactive testing and configuration
2. **Daemon Mode** - Headless operation, ideal for automated scanning and CI/CD pipelines

For this scanner to work, ZAP needs to be running in either mode with the API enabled.

#### GUI Mode
Simply launch the ZAP application and ensure the API is enabled in the options.

#### Daemon Mode
Run ZAP in headless mode using the following commands:

```bash
# On Windows
"C:\Program Files\OWASP\ZAP\zap.bat" -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=false -config api.key=YOUR_API_KEY

# On Linux/macOS
/path/to/zap.sh -daemon -host 127.0.0.1 -port 8080 -config api.disablekey=false -config api.key=YOUR_API_KEY
```

The key parameters for running ZAP in daemon mode are:
- `-daemon`: Run ZAP in headless/daemon mode without GUI
- `-host`: The IP address to bind to (use 0.0.0.0 to allow remote connections)
- `-port`: The port to listen on
- `-config api.disablekey=false`: Require API key for access
- `-config api.key=value`: Set the API key (should match your .env file)

### Running the Scanner

Scan with the default target URL (from environment file):
```bash
python zap_scanner.py
```

Scan a specific target:
```bash
python zap_scanner.py --target https://example.com
```

or using the short option:
```bash
python zap_scanner.py -t https://example.com
```

Additional options:

- `--verbose` (`-v`): enable debug logging in the console and log file.
- `--keep-zap`: skip the shutdown request at the end of the run if you want to keep the ZAP daemon alive for manual review.

## Output

- **Logs**: All scan events are logged to the console and to `logs/zap_scanner.log`
- **Reports**: HTML reports are saved to `reports/zap_report_YYYYMMDD_HHMMSS.html`

## Folder Structure

```
qa-security-scanner/
├── logs/                   # Log files directory
├── reports/                # Generated HTML reports
├── .env                    # Environment configuration (created from .env.example)
├── .env.example            # Example environment configuration
├── zap_scanner.py          # Main scanner script
├── requirements.txt        # Python dependencies
└── README.md               # Documentation
```

## Security Notes

- The ZAP API Key in the .env file should be kept secure and not committed to public repositories
- Only scan websites that you have permission to test
- Review the generated reports for false positives before acting on the results
- The scanner processes a single target per run; execute multiple runs if you need to cover more than one host

## Authenticated Scans

To include authenticated CMS areas in the scan, configure these environment variables:

| Variable | Description |
|----------|-------------|
| `LOGIN_URL` | Absolute URL of the form endpoint that processes the login. When set, authentication is enabled. |
| `LOGIN_USERNAME` / `LOGIN_PASSWORD` | Credentials for the scanner user (required when `LOGIN_URL` is set). |
| `LOGIN_USERNAME_FIELD` / `LOGIN_PASSWORD_FIELD` | Form field names (default: `username` / `password`). |
| `LOGIN_EXTRA_PARAMS` | Optional additional form parameters, formatted as `key=value&foo=bar`. |
| `LOGIN_LOGGED_IN_REGEX` / `LOGIN_LOGGED_OUT_REGEX` | Optional regular expressions to help ZAP detect session state. |

The tool configures a ZAP context with form-based authentication, runs the spider and active scan as the authenticated user, and still supports unauthenticated scans when `LOGIN_URL` is omitted.