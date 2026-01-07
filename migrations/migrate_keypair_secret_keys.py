# SPDX-License-Identifier: GPL-3.0-only
"""Migrate keypair secret_keys from base64 passphrase to hex raw key format.

This migration handles the change in lib_signal_double_ratchet_python where:
1. secret_key encoding changed from base64 to hexlify
2. SQLCipher PRAGMA format changed from passphrase to raw hex mode

Migrates keypairs in:
- StaticKeypairs.keypair_bytes

For each keypair:
1. Deserialize to extract keystore_path, old secret_key
2. Migrate the secret_key string (base64 -> hex)
3. Rekey the underlying SQLCipher keystore database
4. Update and re-serialize the keypair with new secret_key
"""

import argparse
import base64
import os

from peewee import chunked
from sqlcipher3 import dbapi2 as sqlite
from tqdm import tqdm

from base_logger import get_logger
from src.db_models import StaticKeypairs
from src.utils import (
    decrypt_and_deserialize,
    serialize_and_encrypt,
)

logger = get_logger("vault.migrate_keypair_secret_keys")

BATCH_SIZE = 100

migration_errors = []


def migrate_keystore_db(
    keystore_path: str, old_secret_key: str, new_secret_key: str
) -> None:
    """Rekey a SQLCipher keystore database from old to new format.

    Args:
        keystore_path: Path to the keystore database file.
        old_secret_key: Old base64-encoded secret key (passphrase mode).
        new_secret_key: New hex-encoded secret key (raw mode).

    Raises:
        Exception: If rekeying fails.
    """
    if not os.path.exists(keystore_path):
        raise FileNotFoundError(f"Keystore not found: {keystore_path}")

    try:
        conn = sqlite.connect(keystore_path)
        conn.execute(f"PRAGMA key = '{old_secret_key}';")
        conn.execute("PRAGMA cipher_compatibility = 3")

        conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()

        conn.execute(f"PRAGMA rekey = \"x'{new_secret_key}'\";")
        conn.close()

        conn = sqlite.connect(keystore_path)
        conn.execute(f"PRAGMA key = \"x'{new_secret_key}'\";")
        conn.execute("PRAGMA cipher_compatibility = 3")
        conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
        conn.close()

        logger.debug(f"Successfully rekeyed: {keystore_path}")

    except Exception as e:
        raise Exception(f"Failed to rekey {keystore_path}: {e}") from e


def is_already_migrated(secret_key: str) -> bool:
    """Check if secret_key is already in new hex format.

    Args:
        secret_key: The secret key string to check.

    Returns:
        True if already migrated (hex format), False if needs migration (base64).
    """
    # Hex format is 64 chars and contains no '=' padding
    # Base64 format is typically 44 chars with '=' padding
    return len(secret_key) == 64 and "=" not in secret_key


def migrate_keypair_blob(keypair_blob: bytes, identifier: str) -> bytes:
    """Migrate a single keypair blob.

    Args:
        keypair_blob: Encrypted serialized keypair bytes.
        identifier: Human-readable identifier for logging.

    Returns:
        Updated encrypted serialized keypair bytes.

    Raises:
        Exception: If migration fails.
    """
    if not keypair_blob:
        return None

    try:
        keypair_obj = decrypt_and_deserialize(keypair_blob)

        old_secret_key = keypair_obj.secret_key

        if is_already_migrated(old_secret_key):
            logger.debug(f"{identifier} already migrated, skipping")
            return keypair_blob

        old_secret_key_bytes = base64.b64decode(old_secret_key)
        new_secret_key = old_secret_key_bytes.hex()

        migrate_keystore_db(keypair_obj.keystore_path, old_secret_key, new_secret_key)

        keypair_obj.secret_key = new_secret_key

        encrypted_keypair_obj = serialize_and_encrypt(keypair_obj)

        logger.info(f"Successfully migrated {identifier}")
        return encrypted_keypair_obj

    except Exception as e:
        error_msg = f"Failed to migrate {identifier}: {e}"
        logger.error(error_msg)
        migration_errors.append(error_msg)
        raise


def migrate_static_keypairs(dry_run: bool = False):
    """Migrate StaticKeypairs table.

    Args:
        dry_run: If True, only check keypairs without modifying.

    Returns:
        Tuple of (total, migrated, skipped, failed) counts.
    """
    logger.info("=" * 60)
    logger.info("Migrating StaticKeypairs table")
    logger.info("=" * 60)

    keypairs_query = StaticKeypairs.select()
    total = keypairs_query.count()

    if total == 0:
        logger.info("No static keypairs found.")
        return (0, 0, 0, 0)

    logger.info(
        f"Found {total} static keypairs to {'check' if dry_run else 'migrate'}."
    )

    progress_bar = tqdm(total=total, desc="Static keypairs", unit="keypair")
    migrated = 0
    skipped = 0
    failed = 0

    for batch in chunked(keypairs_query, BATCH_SIZE):
        for keypair in batch:
            identifier = f"StaticKeypair kid={keypair.kid}"
            try:
                if dry_run:
                    if keypair.keypair_bytes:
                        kp_obj = decrypt_and_deserialize(keypair.keypair_bytes)

                        if is_already_migrated(kp_obj.secret_key):
                            logger.debug(f"{identifier} already in new format")
                            skipped += 1
                        else:
                            logger.info(f"{identifier} needs migration")
                else:
                    new_blob = migrate_keypair_blob(keypair.keypair_bytes, identifier)
                    if new_blob != keypair.keypair_bytes:
                        keypair.keypair_bytes = new_blob
                        keypair.save(only=["keypair_bytes"])
                        migrated += 1
                    else:
                        skipped += 1

            except Exception as e:
                logger.error(f"Error processing {identifier}: {e}")
                failed += 1

            progress_bar.update(1)

    progress_bar.close()
    return (total, migrated, skipped, failed)


def run_migration(dry_run: bool = False):
    """Migrate all keypair secret_keys.

    Args:
        dry_run: If True, only check keypairs without modifying.
    """
    logger.info("\n" + "=" * 60)
    logger.info(f"Starting keypair migration {'(DRY RUN)' if dry_run else ''}")
    logger.info("=" * 60 + "\n")

    with StaticKeypairs._meta.database.connection_context():
        static_total, static_migrated, static_skipped, static_failed = (
            migrate_static_keypairs(dry_run)
        )

    # Summary
    logger.info("\n" + "=" * 60)
    logger.info(f"Migration {'check' if dry_run else 'complete'} summary")
    logger.info("=" * 60)
    logger.info("\nStaticKeypairs:")
    logger.info(f"  Total: {static_total}")
    logger.info(f"  Migrated: {static_migrated}")
    logger.info(f"  Skipped (already migrated): {static_skipped}")
    logger.info(f"  Failed: {static_failed}")

    if migration_errors:
        logger.error(f"\n{len(migration_errors)} errors occurred:")
        for error in migration_errors[:10]:  # Show first 10 errors
            logger.error(f"  - {error}")
        if len(migration_errors) > 10:
            logger.error(f"  ... and {len(migration_errors) - 10} more errors")
        raise Exception("Migration completed with errors")
    else:
        print("\n✓ All keypairs migrated successfully!\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Migrate keypair secret_keys from base64 to hex format"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check keypairs without modifying them",
    )
    args = parser.parse_args()

    try:
        run_migration(dry_run=args.dry_run)
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        exit(1)
