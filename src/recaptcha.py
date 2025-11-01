"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import requests

from src.utils import get_configs
from base_logger import get_logger

logger = get_logger(__name__)


def is_captcha_enabled():
    """Check if captcha verification is enabled."""
    return get_configs("CAPTCHA_ENABLED", default_value="true").lower() == "true"


def verify_captcha(captcha_token):
    """
    Verify a captcha token Captcha API.

    Args:
        - captcha_token (str): The captcha token to verify.

    Returns:
        - (bool, str): A tuple (success, message).
    """
    try:
        captcha_server_url = get_configs("CAPTCHA_SERVER_URL", strict=True)
        captcha_secret_key = get_configs("CAPTCHA_SECRET_KEY", strict=True)
    except (KeyError, ValueError) as e:
        logger.error("Captcha configuration error: %s", e)
        return False, "Captcha verification service is not configured"

    verify_endpoint = f"{captcha_server_url.rstrip('/')}/v1/verify"

    payload = {"client_secret": captcha_secret_key, "token": captcha_token}

    try:
        response = requests.post(verify_endpoint, json=payload, timeout=10)
        response.raise_for_status()

        result = response.json()
        success = result.get("success", False)
        message = result.get("message", "")

        if not success:
            logger.warning("Captcha verification failed: %s", message)
            return False, message

        return True, "Captcha verified successfully"
    except requests.exceptions.Timeout:
        logger.error("Captcha verification request timed out")
        return False, "Captcha verification timed out. Please try again."
    except requests.exceptions.RequestException as e:
        logger.error("Captcha verification request error: %s", e)
        return False, "Failed to verify captcha. Please try again."
    except Exception as e:
        logger.error("Unexpected error during captcha verification: %s", e)
        return False, "Failed to verify captcha. Please try again."
