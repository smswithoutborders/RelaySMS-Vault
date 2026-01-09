# SPDX-License-Identifier: GPL-3.0-only
"""Ed25519 Signature Keypair Generation."""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from base_logger import get_logger
from src.utils import get_configs, load_and_decode_key

logger = get_logger("ed25519.keygen")


def main() -> None:
    """Generate ed25519 signature keypair if it doesn't exist."""
    keystore_path = get_configs("KEYSTORE_PATH", strict=True)
    signature_key_file = get_configs(
        "SIGNATURE_KEY_FILE", default_value="ed25519_signature.pem"
    )
    encryption_key_file = get_configs("DATA_ENCRYPTION_KEY_PRIMARY_FILE", strict=True)

    ed25519_path = os.path.join(keystore_path, signature_key_file)

    if os.path.exists(ed25519_path):
        logger.info("Ed25519 keypair already exists. Skipping generation.")
        return

    os.makedirs(os.path.dirname(ed25519_path), exist_ok=True)

    logger.info("Generating ed25519 signature keypair...")
    private_key = ed25519.Ed25519PrivateKey.generate()
    encryption_key = load_and_decode_key(encryption_key_file, 32)

    encrypted_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(encryption_key),
    )

    with open(ed25519_path, "wb") as f:
        f.write(encrypted_pem)

    logger.info("Ed25519 keypair stored at %s", ed25519_path)


if __name__ == "__main__":
    main()
