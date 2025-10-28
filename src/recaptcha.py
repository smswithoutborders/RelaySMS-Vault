"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import requests

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
        tuple: (success: bool, message: str, score: float | None)
    """
    if not token:
        logger.warning("reCAPTCHA verification attempted with empty token")
        return False, "reCAPTCHA token is required", None

    if not is_recaptcha_enabled():
        logger.debug("reCAPTCHA verification is disabled")
        return True, "reCAPTCHA verification disabled", None

    try:
        secret_key = get_configs("RECAPTCHA_SECRET_KEY", strict=True)
    except (KeyError, ValueError) as e:
        logger.error("reCAPTCHA secret key not configured: %s", e)
        return False, "reCAPTCHA is not properly configured", None

    payload = {"secret": secret_key, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(RECAPTCHA_VERIFY_URL, params=payload, timeout=10)
        response.raise_for_status()
        result = response.json()

        if not result.get("success"):
            error_code = result.get("error-codes", ["unknown"])[0]
            logger.warning("reCAPTCHA verification failed: %s", error_code)
            return False, "reCAPTCHA verification failed", None

        score = result.get("score")
        logger.info(
            "reCAPTCHA verified. Score: %s, Action: %s", score, result.get("action")
        )

        # Check score threshold for v3
        if score is not None:
            min_score = float(get_configs("RECAPTCHA_MIN_SCORE", default_value="0.5"))
            if score < min_score:
                logger.warning(
                    "reCAPTCHA score %s below threshold %s", score, min_score
                )
                return False, "reCAPTCHA verification failed: score too low", score

        return True, "reCAPTCHA verification successful", score

    except requests.exceptions.Timeout:
        logger.error("reCAPTCHA verification request timed out")
        return False, "reCAPTCHA verification service is unavailable", None

    except requests.exceptions.RequestException as e:
        logger.error("reCAPTCHA verification request failed: %s", e)
        return False, "Failed to verify reCAPTCHA token", None

    except Exception as e:
        logger.exception("Unexpected error during reCAPTCHA verification: %s", e)
        return False, "An unexpected error occurred during verification", None
