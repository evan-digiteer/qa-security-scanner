#!/usr/bin/env python3

"""
Simplified single-target VAPT helper that orchestrates a spider and active scan
through an already-running OWASP ZAP daemon, then saves the resulting report.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import dotenv
import requests
from zapv2 import ZAPv2

BASE_DIR = Path(__file__).resolve().parent
LOGS_DIR = BASE_DIR / "logs"
REPORTS_DIR = BASE_DIR / "reports"

LOGS_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)


class ConfigError(Exception):
    """Raised when runtime configuration is incomplete or invalid."""


def validate_url(value: str) -> bool:
    """Return True when `value` is a syntactically valid absolute URL."""
    try:
        parsed = urllib.parse.urlparse(value)
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False


def timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def build_logger(verbose: bool) -> logging.Logger:
    log_file = LOGS_DIR / "zap_scanner.log"
    
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )

    logger = logging.getLogger("zap_scanner")
    logger.debug("Logger initialised (verbose=%s)", verbose)
    return logger


@dataclass
class LoginConfig:
    login_url: str
    username: str
    password: str
    username_field: str
    password_field: str
    extra_params: Dict[str, str]
    logged_in_indicator: Optional[str]
    logged_out_indicator: Optional[str]


@dataclass
class AppConfig:
    api_url: str
    api_key: str
    target_url: str
    login: Optional[LoginConfig] = None

    @classmethod
    def from_env(cls, args: argparse.Namespace) -> "AppConfig":
        dotenv.load_dotenv()

        target_url = (args.target or os.getenv("DEFAULT_TARGET_URL", "")).strip()
        if not validate_url(target_url):
            raise ConfigError("Target URL is missing or invalid. Provide --target or DEFAULT_TARGET_URL.")

        api_url = os.getenv("ZAP_API_URL", "").strip().rstrip("/")
        if not validate_url(api_url):
            raise ConfigError("ZAP_API_URL must be set to the running ZAP proxy, e.g. http://127.0.0.1:8080")

        api_key = os.getenv("ZAP_API_KEY", "").strip()

        login_config = cls._build_login_config()

        return cls(api_url=api_url, api_key=api_key, target_url=target_url, login=login_config)

    @staticmethod
    def _build_login_config() -> Optional[LoginConfig]:
        login_url = os.getenv("LOGIN_URL", "").strip()
        if not login_url:
            return None

        if not validate_url(login_url):
            raise ConfigError("LOGIN_URL is not a valid URL.")

        username = os.getenv("LOGIN_USERNAME", "").strip()
        password = os.getenv("LOGIN_PASSWORD", "").strip()

        if not username or not password:
            raise ConfigError("LOGIN_USERNAME and LOGIN_PASSWORD must be set when LOGIN_URL is provided.")

        username_field = os.getenv("LOGIN_USERNAME_FIELD", "username").strip() or "username"
        password_field = os.getenv("LOGIN_PASSWORD_FIELD", "password").strip() or "password"

        extra_params_env = os.getenv("LOGIN_EXTRA_PARAMS", "").strip()
        extra_params: Dict[str, str] = {}
        if extra_params_env:
            for pair in extra_params_env.split("&"):
                if not pair:
                    continue
                if "=" not in pair:
                    raise ConfigError(f"Invalid key=value pair in LOGIN_EXTRA_PARAMS: {pair}")
                key, value = pair.split("=", 1)
                extra_params[key] = value

        logged_in_indicator = os.getenv("LOGIN_LOGGED_IN_REGEX", "").strip() or None
        logged_out_indicator = os.getenv("LOGIN_LOGGED_OUT_REGEX", "").strip() or None

        return LoginConfig(
            login_url=login_url,
            username=username,
            password=password,
            username_field=username_field,
            password_field=password_field,
            extra_params=extra_params,
            logged_in_indicator=logged_in_indicator,
            logged_out_indicator=logged_out_indicator,
        )


class ZapScanner:
    def __init__(self, config: AppConfig, logger: logging.Logger) -> None:
        self.config = config
        self.logger = logger
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "qa-security-scanner/1.0"

        proxies = {"http": self.config.api_url, "https": self.config.api_url}
        self.zap = ZAPv2(apikey=self.config.api_key, proxies=proxies)
        self.context_name: Optional[str] = None
        self.context_id: Optional[str] = None
        self.user_id: Optional[str] = None
        self.forced_user_mode_enabled: bool = False

    def verify_connection(self) -> None:
        url = f"{self.config.api_url}/JSON/core/view/version/"
        self.logger.info("Connecting to ZAP at %s", url)

        try:
            response = self.session.get(url, params={"apikey": self.config.api_key}, timeout=10)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise ConfigError(f"Unable to reach ZAP API at {self.config.api_url}: {exc}") from exc

        zap_version = response.json().get("version", "unknown")
        self.logger.info("Connected to ZAP version %s", zap_version)

    def configure_authentication(self) -> None:
        if not self.config.login:
            self.logger.debug("No login configuration provided; proceeding unauthenticated.")
            return

        login = self.config.login
        self.context_name = "CMS Auth Context"
        self.logger.info("Setting up authenticated context for %s", login.login_url)

        self.context_id = self.zap.context.new_context(self.context_name)
        if not self.context_id:
            raise RuntimeError("Failed to create ZAP context for authentication.")

        include_patterns = {
            f"\\Q{self.config.target_url}\\E.*",
            f"\\Q{login.login_url}\\E.*",
        }
        for pattern in include_patterns:
            self.zap.context.include_in_context(self.context_name, pattern)

        login_request_data = {
            login.username_field: "{{username}}",
            login.password_field: "{{password}}",
        }
        login_request_data.update(login.extra_params)

        login_request_template = urllib.parse.urlencode(login_request_data)
        auth_config_params = f"loginUrl={login.login_url}&loginRequestData={login_request_template}"

        self.zap.authentication.set_authentication_method(
            self.context_id,
            "formBasedAuthentication",
            auth_config_params,
        )

        self.zap.sessionManagement.set_session_management_method(
            self.context_id,
            "cookieBasedSessionManagement",
            "",
        )

        if login.logged_in_indicator:
            self.zap.authentication.set_logged_in_indicator(self.context_id, login.logged_in_indicator)

        if login.logged_out_indicator:
            self.zap.authentication.set_logged_out_indicator(self.context_id, login.logged_out_indicator)

        self.user_id = self.zap.users.new_user(self.context_id, "scanner-user")

        credential_params = urllib.parse.urlencode(
            {
                "username": login.username,
                "password": login.password,
            }
        )

        self.zap.users.set_authentication_credentials(self.context_id, self.user_id, credential_params)
        self.zap.users.set_user_enabled(self.context_id, self.user_id, True)
        self.zap.forcedUser.set_forced_user(self.context_id, self.user_id)
        self.zap.forcedUser.set_forced_user_mode_enabled(True)
        self.logger.info("Forced user mode enabled for authenticated scans.")
        self.forced_user_mode_enabled = True

    def clear_session(self) -> None:
        self.logger.debug("Clearing ZAP session")
        self.zap.core.new_session(name=None, overwrite=True)

    def _wait_for_completion(self, poller, label: str, interval: float = 2.0) -> None:
        while True:
            status = int(poller())
            self.logger.debug("%s progress: %s%%", label, status)
            if status >= 100:
                self.logger.info("%s completed", label.capitalize())
                return
            time.sleep(interval)

    def priming_request(self) -> None:
        if self.config.login:
            self.logger.info("Priming ZAP with login URL %s", self.config.login.login_url)
            self.zap.core.access_url(url=self.config.login.login_url)
            time.sleep(2)

        self.logger.info("Priming ZAP with %s", self.config.target_url)
        self.zap.core.access_url(url=self.config.target_url)
        time.sleep(2)

    def run_spider(self) -> None:
        self.logger.info("Starting spider for %s", self.config.target_url)

        if self.context_id and self.user_id:
            scan_id = self.zap.spider.scan_as_user(self.context_id, self.user_id, self.config.target_url)
        else:
            scan_id = self.zap.spider.scan(url=self.config.target_url)

        if scan_id is None or scan_id == "":
            raise RuntimeError("ZAP did not return a valid spider scan id")

        self._wait_for_completion(lambda: self.zap.spider.status(scan_id), "spider")

        urls = self.zap.spider.results(scan_id) or []
        self.logger.info("Spider discovered %d URL(s)", len(urls))

    def run_active_scan(self) -> Dict[str, int]:
        self.logger.info("Starting active scan for %s", self.config.target_url)
        if self.context_id and self.user_id:
            scan_id = self.zap.ascan.scan_as_user(self.context_id, self.user_id, self.config.target_url, recurse=True)
        else:
            scan_id = self.zap.ascan.scan(url=self.config.target_url, recurse=True)

        if scan_id is None or scan_id == "":
            raise RuntimeError("ZAP did not return a valid active scan id")

        self._wait_for_completion(lambda: self.zap.ascan.status(scan_id), "active scan", interval=5.0)

        alerts = self.zap.core.alerts()
        summary: Dict[str, int] = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for alert in alerts:
            risk = alert.get("risk")
            if risk in summary:
                summary[risk] += 1

        self.logger.info("Active scan complete. Alert summary: %s", summary)
        return summary

    def generate_report(self) -> Path:
        report_path = REPORTS_DIR / f"zap_report_{timestamp()}.html"
        self.logger.info("Saving HTML report to %s", report_path)

        report_html = self.zap.core.htmlreport()
        report_path.write_text(report_html, encoding="utf-8")
        return report_path

    def shutdown(self) -> None:
        self.logger.info("Requesting ZAP shutdown")
        self.disable_forced_user_mode()
        try:
            self.zap.core.shutdown()
        except Exception as exc:  # noqa: broad-except -- best effort shutdown
            self.logger.warning("ZAP shutdown request failed: %s", exc)

    def disable_forced_user_mode(self) -> None:
        if not self.forced_user_mode_enabled:
            return

        try:
            self.zap.forcedUser.set_forced_user_mode_enabled(False)
            self.forced_user_mode_enabled = False
        except Exception as exc:  # noqa: broad-except -- best effort
            self.logger.debug("Could not disable forced user mode: %s", exc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a single OWASP ZAP spider + active scan against a target URL.")
    parser.add_argument("--target", "-t", help="Target URL to scan (falls back to DEFAULT_TARGET_URL env var)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--keep-zap", action="store_true", help="Do not send shutdown request to ZAP when done")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logger = build_logger(args.verbose)
    scanner: Optional[ZapScanner] = None
    
    try:
        config = AppConfig.from_env(args)
        scanner = ZapScanner(config, logger)

        scanner.verify_connection()
        scanner.clear_session()
        scanner.configure_authentication()
        scanner.priming_request()
        scanner.run_spider()
        alert_summary = scanner.run_active_scan()
        report_path = scanner.generate_report()

        logger.info("Scan finished successfully. Report saved to %s", report_path)
        print(f"Scan complete. Report: {report_path}")
        print(f"Alert summary: {alert_summary}")
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.exception("Scan failed: %s", exc)
        sys.exit(1)
    finally:
        if not scanner:
            return

        if args.keep_zap:
            scanner.disable_forced_user_mode()
        else:
            scanner.shutdown()


if __name__ == "__main__":
    main()
