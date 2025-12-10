# SPDX-License-Identifier: GPL-3.0-only
"""Cryptographic utilities."""

import hashlib
import hmac
import os

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from Crypto.Cipher import AES
from cryptography.fernet import Fernet

from base_logger import get_logger

logger = get_logger(__name__)

TIME_COST = int(os.getenv("ARGON2_TIME_COST", "3"))
MEMORY_COST = int(os.getenv("ARGON2_MEMORY_COST", "65536"))
PARALLELISM = int(os.getenv("ARGON2_PARALLELISM", "2"))
HASH_LENGTH = int(os.getenv("ARGON2_HASH_LENGTH", "32"))
SALT_LENGTH = int(os.getenv("ARGON2_SALT_LENGTH", "16"))

argon2_ph = PasswordHasher(
    time_cost=TIME_COST,
    memory_cost=MEMORY_COST,
    parallelism=PARALLELISM,
    hash_len=HASH_LENGTH,
    salt_len=SALT_LENGTH,
    type=Type.ID,
)


def encrypt_aes(key, plaintext, is_bytes=False):
    """
    Encrypts a plaintext string or bytes using AES-256 encryption.

    Args:
        key (bytes): The encryption key (must be 32 bytes long).
        plaintext (str or bytes): The plaintext to be encrypted.
        is_bytes (bool): If True, plaintext is treated as bytes; otherwise, it's encoded as UTF-8.

    Returns:
        bytes: The encrypted ciphertext.
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes long")

    if not isinstance(plaintext, (str, bytes)):
        raise TypeError("Plaintext must be either a string or bytes")

    if not is_bytes and isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    logger.debug("Encrypting plaintext using AES-256...")
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return cipher.nonce + tag + ciphertext


def decrypt_aes(key, ciphertext, is_bytes=False):
    """
    Decrypts a ciphertext string or bytes using AES-256 decryption.

    Args:
        key (bytes): The decryption key (must be 32 bytes long).
        ciphertext (bytes): The encrypted ciphertext (nonce + tag + ciphertext).
        is_bytes (bool): If True, returns decrypted bytes; otherwise, returns a decoded string.

    Returns:
        str or bytes: The decrypted plaintext (either as a string or bytes).
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes long")

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be in bytes")

    logger.debug("Decrypting ciphertext using AES-256...")
    nonce = ciphertext[:16]
    tag = ciphertext[16:32]
    ciphertext = ciphertext[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    if is_bytes:
        return plaintext
    return plaintext.decode("utf-8")


def generate_hmac(key, message):
    """
    Generates an HMAC for a given message using the provided key.

    Args:
        key (bytes): The key for HMAC generation (must be 32 bytes long).
        message (str): The message for which the HMAC is to be generated.

    Returns:
        str: The generated HMAC as a hexadecimal string.
    """
    if len(key) != 32:
        raise ValueError("HMAC key must be 32 bytes long")

    logger.debug("Generating HMAC for the message...")
    return hmac.new(key, message.encode("utf-8"), hashlib.sha512).hexdigest()


def verify_hmac(key, message, hmac_to_verify):
    """
    Verifies the HMAC of a given message against a provided HMAC.

    Args:
        key (bytes): The key for HMAC generation (must be 32 bytes long).
        message (str): The message whose HMAC is to be verified.
        hmac_to_verify (str): The HMAC to verify against.

    Returns:
        bool: True if the HMAC is valid, False otherwise.
    """
    if len(key) != 32:
        raise ValueError("HMAC key must be 32 bytes long")

    logger.debug("Verifying HMAC for the message...")
    generated_hmac = generate_hmac(key, message)
    return hmac.compare_digest(generated_hmac, hmac_to_verify)


def encrypt_fernet(key, plaintext):
    """
    Encrypts a plaintext string using Fernet encryption.

    Args:
        key (bytes): The encryption key (must be 32 bytes long).
        plaintext (str): The plaintext string to be encrypted.

    Returns:
        bytes: The encrypted ciphertext.
    """
    logger.debug("Encrypting plaintext using Fernet encryption...")
    fernet = Fernet(key)
    return fernet.encrypt(plaintext.encode("utf-8"))


def decrypt_fernet(key, ciphertext):
    """
    Decrypts a ciphertext string using Fernet encryption.

    Args:
        key (bytes): The decryption key (must be 32 bytes long).
        ciphertext (bytes): The encrypted ciphertext.

    Returns:
        str: The decrypted plaintext string.
    """
    logger.debug("Decrypting ciphertext using Fernet encryption...")
    fernet = Fernet(key)
    return fernet.decrypt(ciphertext).decode("utf-8")


def hash_password_argon2id(pepper: bytes, password: str) -> str:
    """Hash a password using Argon2id with the provided pepper."""
    if not pepper:
        raise ValueError("Pepper cannot be empty")

    if not password:
        raise ValueError("Password cannot be empty")

    return argon2_ph.hash(pepper + password.encode())


def verify_password_argon2id(
    pepper: bytes, password: str, password_hash: str
) -> tuple[bool, bool]:
    """
    Verify a password against an Argon2id hash.

    Returns:
        success (bool): True if the password matches
        needs_rehash (bool): True if the hash should be upgraded
    """
    if not pepper or not password or not password_hash:
        return False, False

    try:
        argon2_ph.verify(password_hash, pepper + password.encode())

        needs_rehash = argon2_ph.check_needs_rehash(password_hash)
        return True, needs_rehash

    except (VerifyMismatchError, InvalidHashError):
        return False, False
    except Exception as e:
        logger.error(f"Unexpected error during password verification: {e}")
        return False, False
