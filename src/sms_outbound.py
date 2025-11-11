"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import requests
import phonenumbers
from phonenumbers import geocoder
from src.utils import get_configs, get_list_config
from base_logger import get_logger


QUEUEDROID_API_URL = get_configs(
    "QUEUEDROID_API_URL", default_value="https://api.queuedroid.com/v1/messages/send"
)
QUEUEDROID_API_KEY = get_configs("QUEUEDROID_API_KEY")
QUEUEDROID_EXCHANGE_ID = get_configs("QUEUEDROID_EXCHANGE_ID")
QUEUEDROID_QUEUE_ID = get_configs("QUEUEDROID_QUEUE_ID")
QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES = get_list_config(
    "QUEUEDROID_SUPPORTED_VERIFICATION_REGION_CODES"
)

logger = get_logger(__name__)


def send_with_queuedroid(phone_number: str, message: str) -> bool:
    """
    Sends a message using Queuedroid to a specified phone number.

    Args:
        phone_number (str): The recipient's phone number in E.164 format (e.g., +237123456789).
        message (str): The content to be sent to the specified phone number.

    Returns:
        bool: True if the message was sent successfully, False otherwise.
    """
    try:
        data = {
            "content": message,
            "exchange_id": QUEUEDROID_EXCHANGE_ID,
            "queue_id": QUEUEDROID_QUEUE_ID,
            "phone_number": phone_number,
        }
        headers = {"Authorization": f"Bearer {QUEUEDROID_API_KEY}"}
        response = requests.post(
            QUEUEDROID_API_URL, json=data, headers=headers, timeout=10
        )

        if response.ok:
            logger.info("Message sent successfully via Queuedroid.")
            return True
        response.raise_for_status()
        return False
    except requests.RequestException as exc:
        logger.exception("Error sending message via Queuedroid: %s", exc)
        return False


def get_phonenumber_region_code(phone_number: str) -> tuple:
    """
    Get the region code for a given phone number.

    Args:
        phone_number (str): The phone number in E.164 format.

    Returns:
        tuple: A tuple containing the region code (str) and country name (str).
    """
    parsed_number = phonenumbers.parse(phone_number)
    region_code = geocoder.region_code_for_number(parsed_number)
    country_name = geocoder.description_for_number(parsed_number, "en")
    return region_code, country_name
