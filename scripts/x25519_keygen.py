# SPDX-License-Identifier: GPL-3.0-only
"""X25519 Keypair Generation, Export, and Testing CLI."""

import argparse
import base64
import json
import os
import random
import uuid

from smswithoutborders_libsig.keypairs import x25519

from base_logger import get_logger
from src.db_models import StaticKeypairs
from src.utils import decrypt_and_deserialize, get_configs, serialize_and_encrypt

logger = get_logger("static.x25519.keygen")

STATIC_KEYSTORE_PATH = get_configs("STATIC_X25519_KEYSTORE_PATH", strict=True)
DEFAULT_EXPORT_PATH = os.path.join(STATIC_KEYSTORE_PATH, "exported_public_keys.json")


def generate_keypair(kid: int, keystore_path: str, version: str) -> None:
    """Generates a keypair, encrypts it, and stores it in the database."""
    try:
        keystore_db_path = os.path.join(keystore_path, f"{uuid.uuid4()}.db")
        keypair_obj = x25519(keystore_db_path)
        keypair_obj.init()

        keypair_ciphertext = serialize_and_encrypt(keypair_obj)

        StaticKeypairs.create_keypair(
            kid=kid, keypair_bytes=keypair_ciphertext, status="active", version=version
        )
        logger.debug("Successfully generated and stored keypair %d.", kid)

    except Exception as e:
        logger.exception("Failed to generate keypair %d: %s", kid, e)

        if keystore_db_path and os.path.exists(keystore_db_path):
            try:
                os.remove(keystore_db_path)
                logger.info(
                    "Rolled back and deleted keystore file: %s", keystore_db_path
                )
            except Exception as rollback_error:
                logger.error(
                    "Failed to delete keystore file %s: %s",
                    keystore_db_path,
                    rollback_error,
                )


def generate_keypairs(count: int, version: str) -> None:
    """Generates and stores multiple keypairs."""
    if not version.startswith("v"):
        logger.error("version must start with 'v'. e.g v1.")
        return

    keystore_path = os.path.join(STATIC_KEYSTORE_PATH, version)
    if os.path.exists(keystore_path) and os.listdir(keystore_path):
        logger.info(
            "Keypair generation skipped: '%s' is not empty. To overwrite the content, "
            "delete the directory or use a different one.",
            keystore_path,
        )
        return

    os.makedirs(keystore_path, exist_ok=True)

    for i in range(count):
        generate_keypair(i, keystore_path, version)

    logger.info("Successfully generated %d keypairs.", count)


def export_public_keys_to_file(file_path: str, yes: bool, skip_if_exists: bool) -> None:
    """Exports all public keys grouped by version to a specified JSON file."""
    file_path = file_path or DEFAULT_EXPORT_PATH
    try:
        dir_path = os.path.dirname(file_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        if os.path.exists(file_path):
            if skip_if_exists:
                logger.info("Export skipped: %s already exists.", file_path)
                return
            if not yes:
                confirm = (
                    input(
                        f"{file_path} already exists. Do you want to replace it? (y/N): "
                    )
                    .strip()
                    .lower()
                )
                if confirm != "y":
                    logger.info("Export aborted by user.")
                    return

        active_keypairs = StaticKeypairs.get_keypairs(status="active")

        public_keys = [
            {
                "kid": keypair.kid,
                "keypair": base64.b64encode(
                    decrypt_and_deserialize(keypair.keypair_bytes).get_public_key()
                ).decode("utf-8"),
                "status": keypair.status,
                "version": keypair.version,
            }
            for keypair in active_keypairs
        ]

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(public_keys, f, indent=2)

        logger.info("Public keys exported successfully to %s.", file_path)

    except Exception as e:
        logger.exception("Failed to export public keys: %s", e)
        raise


def test_keypairs() -> None:
    """Performs a key agreement test using two randomly selected keypairs."""
    try:
        keypairs = StaticKeypairs.get_keypairs(status="active")
        if len(keypairs) < 2:
            raise ValueError("Not enough keypairs for key agreement test.")

        keypair1, keypair2 = random.sample(keypairs, 2)

        keypair_1 = decrypt_and_deserialize(keypair1.keypair_bytes)
        keypair_2 = decrypt_and_deserialize(keypair2.keypair_bytes)

        shared_secret_1 = keypair_1.agree(keypair_2.get_public_key())
        shared_secret_2 = keypair_2.agree(keypair_1.get_public_key())

        if shared_secret_1 == shared_secret_2:
            logger.info("Key agreement successful: shared secret matches.")
        else:
            logger.error("Key agreement failed: shared secrets do not match.")

    except Exception as e:
        logger.exception("Key agreement test failed: %s", e)
        raise


def main() -> None:
    """CLI entry point for key management."""
    parser = argparse.ArgumentParser(description="x25519 Key Management CLI")
    subparser = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparser.add_parser("generate", help="Generate keypairs")
    generate_parser.add_argument(
        "-n", "--number", type=int, default=255, help="Number of keypairs to generate"
    )
    generate_parser.add_argument(
        "-v", "--version", type=str, required=True, help="Keypair version"
    )

    export_parser = subparser.add_parser("export", help="Export public keys")
    export_parser.add_argument(
        "-f", "--file", type=str, default=None, help="Path to save the public keys file"
    )
    export_parser.add_argument(
        "-y", "--yes", action="store_true", help="Overwrite the file without prompting"
    )
    export_parser.add_argument(
        "--skip-if-exists", action="store_true", help="Skip export if file exists"
    )

    subparser.add_parser("test", help="Test key agreement")

    args = parser.parse_args()

    commands = {
        "generate": lambda: generate_keypairs(args.number, args.version),
        "export": lambda: export_public_keys_to_file(
            args.file, args.yes, args.skip_if_exists
        ),
        "test": test_keypairs,
    }

    commands[args.command]()


if __name__ == "__main__":
    main()
