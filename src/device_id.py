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


def derive_device_id_v1(
    client_id_pub_key: bytes, message: str = "RelaySMS DID v1", truncate_bits: int = 128
) -> bytes:
    """
    Derive a device ID according to the RelaySMS DID v1 spec.

    Spec:
        HO = SHA-256(Message || CI_pk)
        DID = Truncate(HO, 128–160 bits)

    Args:
        client_id_pub_key (bytes): The client's public key (CI_pk).
        message (str): Fixed message string ("RelaySMS DID v1").
        truncate_bits (int): Number of bits to truncate to (128–160).

    Returns:
        bytes: The derived device ID.
    """
    try:
        if not 128 <= truncate_bits <= 160:
            raise ValueError("truncate_bits must be between 128 and 160")

        logger.debug("Starting derivation of device ID (RelaySMS DID v1)...")

        data = message.encode("utf-8") + client_id_pub_key
        hash_output = hashlib.sha256(data).digest()
        truncate_bytes = truncate_bits // 8
        device_id = hash_output[:truncate_bytes]

        logger.debug(
            "Derived device ID with %d bits (%d bytes)", truncate_bits, truncate_bytes
        )

        return device_id

    except Exception as e:
        logger.exception("Error deriving device ID: %s", e)
        raise
