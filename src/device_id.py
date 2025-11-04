"""
Module for handling Device ID.
"""

import hmac
import hashlib
from base_logger import get_logger

logger = get_logger(__name__)


def compute_device_id(secret_key: bytes, identifier: str, public_key: bytes) -> bytes:
    """
    Compute a device ID using HMAC and SHA-256.

    Args:
        secret_key (bytes): The secret key used for HMAC.
        identifier (str): The identifier (phone number or email) to be included in the HMAC input.
        public_key (bytes): The public key to be included in the HMAC input.

    Returns:
        bytes: The bytes representation of the HMAC digest.
    """
    try:
        logger.debug("Starting computation of device ID...")
        combined_input = identifier.encode("utf-8") + public_key
        hmac_object = hmac.new(secret_key, combined_input, hashlib.sha256)
        return hmac_object.hexdigest()
    except Exception as e:
        logger.exception("Error computing device ID: %s", e)
        raise e
