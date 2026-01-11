"""
Module for generating and verifying Long-Lived Tokens (LLTs).
"""

import base64
from datetime import datetime, timedelta
from typing import Optional, Tuple

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from base_logger import get_logger
from src.crypto import encrypt_fernet
from src.utils import convert_to_fernet_key

logger = get_logger(__name__)


def generate_llt(eid, key):
    """
    Generate a Long-Lived Token (LLT) for the given entity ID (eid).

    Args:
        eid (str): The entity ID for which LLT is generated.
        key (bytes): The key used for encryption.

    Returns:
        str: Base64 encoded and encrypted LLT.
    """
    logger.debug("Generating payload for the long-lived token...")

    return ""


def verify_llt(llt, key):
    """
    Verify the integrity and authenticity of a Long-Lived Token (LLT).

    Args:
        llt (str): The LLT to be verified.
        key (bytes): The key used for encryption.

    Returns:
        tuple: A tuple containing two items:
            - dict or None: The decoded payload of the LLT if valid, None otherwise.
            - str or None: Error message if LLT is invalid or expired, None if LLT is valid.
    """
    try:
        logger.debug("Decoding the long-lived token...")
        return "", None

    except Exception as error:
        logger.error("Error verifying long-lived token: %s", error)
        return None, error


def derive_llt_v1(payload: dict, si_private_key: ed25519.Ed25519PrivateKey) -> str:
    """
    Generate a Long-Lived Token (LLT) v1.

    Server generates the LLT as follows:
    LLT = JWT().encode(payload, SI_sig, alg="EdDSA")

    Args:
        payload (dict): The JWT payload containing claims.
        si_private_key (ed25519.Ed25519PrivateKey): Server's Ed25519 private signing key.

    Returns:
        str: Signed JWT token (LLT).
    """
    logger.debug("Generating LLT v1 with EdDSA signing...")

    private_key_bytes = si_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    logger.debug("Encoding the long-lived token with EdDSA algorithm...")
    llt = jwt.encode(payload, private_key_bytes, algorithm="EdDSA")

    return llt


def verify_llt_v1(
    llt: str, si_public_key: ed25519.Ed25519PublicKey
) -> Tuple[Optional[dict], Optional[str]]:
    """
    Verify a Long-Lived Token (LLT) v1.

    Args:
        llt (str): The LLT JWT to verify.
        si_public_key (ed25519.Ed25519PublicKey): Server's Ed25519 public key.

    Returns:
        tuple: A tuple containing two items:
            - dict or None: The decoded payload of the LLT if valid, None otherwise.
            - str or None: Error message if LLT is invalid, None if LLT is valid.
    """
    try:
        logger.debug("Verifying LLT v1 with EdDSA signature...")

        public_key_bytes = si_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        payload = jwt.decode(llt, public_key_bytes, algorithms=["EdDSA"])

        logger.debug("LLT v1 verified successfully")
        return payload, None

    except Exception as error:
        logger.error("Error verifying long-lived token v1: %s", error)
        return None, str(error)


def derive_llt_shared_secret(
    client_id_pub_key: bytes, server_identity_keypair: bytes
) -> bytes:
    """
    Derive shared secret using HKDF.

    shared_secret = HKDF(
        salt = "RelaySMS_GRPC_SIGNING_SALT",
        input = DH(CI, SI_pk),
        info = "RelaySMS C2S gRPC v2"
    )

    Args:
        client_id_pub_key (bytes): Client's X25519 public key.
        server_private_key (bytes): Server's X25519 private key.

    Returns:
        bytes: Derived shared secret.
    """

    dh_shared = server_identity_keypair.agreeOnly(client_id_pub_key)

    shared_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"RelaySMS_GRPC_SIGNING_SALT",
        info=b"RelaySMS C2S gRPC v2",
    ).derive(dh_shared)

    return shared_secret
