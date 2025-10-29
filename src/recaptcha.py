"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import requests
import json

from src.utils import get_configs
from base_logger import get_logger

logger = get_logger(__name__)

RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def is_recaptcha_enabled():
    """Check if reCAPTCHA verification is enabled."""
    return get_configs("RECAPTCHA_ENABLED", default_value="true").lower() == "true"


def verify_recaptcha_token(token, remote_ip=None):
    """
    Verify a reCAPTCHA token with Google's reCAPTCHA API.

    Args:
        token (str): The reCAPTCHA token to verify.
        remote_ip (str, optional): The user's IP address.

    Returns:
        tuple: (success: bool, message: str)
    """
    if not token:
        logger.warning("reCAPTCHA verification attempted with empty token")
        return False, "reCAPTCHA token is required"

    if not is_recaptcha_enabled():
        logger.debug("reCAPTCHA verification is disabled")
        return True, "reCAPTCHA verification disabled"

    try:
        secret_key = get_configs("RECAPTCHA_SECRET_KEY", strict=True)
    except (KeyError, ValueError) as e:
        logger.error("reCAPTCHA secret key not configured: %s", e)
        return False, "reCAPTCHA is not properly configured"

    payload = {"secret": secret_key, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(RECAPTCHA_VERIFY_URL, params=payload, timeout=10)
        response.raise_for_status()

        if not response.content:
            logger.error("reCAPTCHA API returned empty response")
            return (
                False,
                "reCAPTCHA service is temporarily unavailable. Please try again.",
            )

        try:
            # Remove XSSI protection prefix if present (e.g., )]}'  )
            response_text = response.text.strip()
            if response_text.startswith(")]}'"):
                response_text = response_text[4:].strip()

            result = json.loads(response_text)
        except (ValueError, json.JSONDecodeError) as json_err:
            logger.error(
                "Failed to parse reCAPTCHA response: %s. Response: %s",
                json_err,
                response.text,
            )
            return (
                False,
                "reCAPTCHA service is temporarily unavailable. Please try again.",
            )

        if not result.get("success"):
            error_code = result.get("error-codes", ["unknown"])[0]
            logger.warning("reCAPTCHA verification failed: %s", error_code)
            return False, "reCAPTCHA verification failed"

        logger.info("reCAPTCHA verified successfully.")

        return True, "reCAPTCHA verification successful"

    except requests.exceptions.Timeout:
        logger.error("reCAPTCHA verification request timed out")
        return False, "reCAPTCHA verification service is unavailable"

    except requests.exceptions.RequestException as e:
        logger.error("reCAPTCHA verification request failed: %s", e)
        return False, "Failed to verify reCAPTCHA token"

    except Exception as e:
        logger.exception("Unexpected error during reCAPTCHA verification: %s", e)
        return False, "An unexpected error occurred during verification"
