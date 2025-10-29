"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import base64
import requests

from src.utils import get_configs
from base_logger import get_logger

logger = get_logger(__name__)


def is_captcha_enabled():
    """Check if captcha verification is enabled."""
    return get_configs("RECAPTCHA_ENABLED", default_value="true").lower() == "true"


def get_captcha():
    """
    Request a new captcha from the Libre Captcha API.

    Returns:
        tuple: (captcha_data: dict or None, message: str)
            captcha_data contains:
                - id: The captcha identifier (uuid)
                - image: Base64 encoded PNG image (from the API this is 'png' field)
    """

    if not is_captcha_enabled():
        logger.debug("Captcha verification is disabled")
        return None, "Captcha verification disabled"

    try:
        libre_captcha_url = get_configs("LIBRE_CAPTCHA_URL", strict=True)
    except (KeyError, ValueError) as e:
        logger.error("Libre Captcha URL not configured: %s", e)
        return None, "Captcha service is not properly configured"

    captcha_endpoint = f"{libre_captcha_url.rstrip('/')}/v2/captcha"

    payload = {
        "media": "image/png",
        "level": "easy",
        "input_type": "text",
        "size": "350x100",
    }

    try:
        response = requests.post(captcha_endpoint, json=payload, timeout=10)
        response.raise_for_status()

        result = response.json()

        if "id" not in result:
            logger.error("Libre Captcha API response missing 'id' field")
            return None, "Invalid captcha response format"

        captcha_id = result["id"]

        media_endpoint = f"{libre_captcha_url.rstrip('/')}/v2/media"
        media_response = requests.get(
            media_endpoint, params={"id": captcha_id}, timeout=10
        )
        media_response.raise_for_status()
        image_base64 = base64.b64encode(media_response.content).decode("utf-8")

        captcha_data = {"id": captcha_id, "image": image_base64}

        logger.info("Captcha retrieved successfully. ID=%s", captcha_id)
        return captcha_data, "Captcha retrieved successfully"

    except requests.exceptions.Timeout:
        logger.error("Libre Captcha request timed out")
        return None, "Captcha service is unavailable"

    except requests.exceptions.RequestException as e:
        logger.error("Libre Captcha request failed: %s", e)
        return None, "Failed to retrieve captcha"

    except Exception as e:
        logger.exception("Unexpected error during Libre Captcha retrieval: %s", e)
        return None, "Failed to retrieve captcha"


def verify_captcha(captcha_id, captcha_answer):
    """
    Verify a captcha answer with the Libre Captcha API.

    Args:
        captcha_id (str): The captcha identifier (uuid).
        captcha_answer (str): The user's answer to the captcha.

    Returns:
        tuple: (success: bool, message: str)
    """
    if not captcha_id or not captcha_answer:
        logger.warning("Captcha verification attempted with missing data")
        return False, "Captcha ID and answer are required"

    if not is_captcha_enabled():
        logger.debug("Captcha verification is disabled")
        return True, "Captcha verification disabled"

    try:
        libre_captcha_url = get_configs("LIBRE_CAPTCHA_URL", strict=True)
    except (KeyError, ValueError) as e:
        logger.error("Libre Captcha URL not configured: %s", e)
        return False, "Captcha service is not properly configured"

    answer_endpoint = f"{libre_captcha_url.rstrip('/')}/v2/answer"

    payload = {"id": captcha_id, "answer": captcha_answer}

    try:
        response = requests.post(answer_endpoint, json=payload, timeout=10)
        response.raise_for_status()

        result = response.json()
        result_value = result.get("result", "").lower()

        if result_value == "true":
            logger.info("Captcha verified successfully for ID=%s", captcha_id)
            return True, "Captcha verification successful"

        if result_value == "expired":
            logger.warning("Captcha expired for ID=%s", captcha_id)
            return False, "Captcha has expired. Please request a new one."

        logger.warning("Captcha verification failed for ID=%s", captcha_id)
        return False, "Captcha verification failed. Incorrect answer."

    except requests.exceptions.Timeout:
        logger.error("Libre Captcha verification request timed out")
        return False, "Captcha verification service is unavailable"

    except requests.exceptions.RequestException as e:
        logger.error("Libre Captcha verification request failed: %s", e)
        return False, "Failed to verify captcha"

    except Exception as e:
        logger.exception("Unexpected error during Libre Captcha verification: %s", e)
        return False, "Failed to verify captcha"
