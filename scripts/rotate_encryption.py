# SPDX-License-Identifier: GPL-3.0-only
"""Rotate encryption of all encrypted data in the vault."""

import argparse
import base64

from peewee import chunked
from tqdm import tqdm

from base_logger import get_logger
from src.crypto import decrypt_aes
from src.db_models import Entity, StaticKeypairs, Token
from src.utils import (
    encrypt_and_encode,
    encrypt_data,
    get_configs,
    load_and_decode_key,
    load_key,
)

logger = get_logger("vault.rotate_encryption")

BATCH_SIZE = 500

rotation_errors = {"entities": [], "tokens": [], "static_keypairs": []}

NO_DECODE = False


def decode_and_decrypt(encoded_ciphertext: str) -> str:
    """Decode and decrypt Base64-encoded ciphertext.

    Args:
        encoded_ciphertext: Base64-encoded ciphertext.

    Returns:
        Decrypted plaintext.
    """
    if NO_DECODE:
        encryption_key = load_key(get_configs("DATA_ENCRYPTION_KEY_SECONDARY_FILE"), 32)
    else:
        encryption_key = load_and_decode_key(
            get_configs("DATA_ENCRYPTION_KEY_SECONDARY_FILE"), 32
        )

    ciphertext = base64.b64decode(encoded_ciphertext)
    return decrypt_aes(encryption_key, ciphertext)


def decrypt_data(encrypted_data: bytes) -> bytes:
    """Decrypt data from database.

    Args:
        encrypted_data: Encrypted data bytes.

    Returns:
        Decrypted data bytes.
    """
    if NO_DECODE:
        encryption_key = load_key(
            get_configs("DATA_ENCRYPTION_KEY_SECONDARY_FILE", strict=True), 32
        )
    else:
        encryption_key = load_and_decode_key(
            get_configs("DATA_ENCRYPTION_KEY_SECONDARY_FILE", strict=True), 32
        )
    return decrypt_aes(encryption_key, encrypted_data, is_bytes=True)


def rotate_entity_encryption():
    """Rotate encryption for entity data."""

    with Entity._meta.database.connection_context():
        entities_query = Entity.select().where(
            (Entity.country_code.is_null(False))
            | (Entity.publish_keypair.is_null(False))
            | (Entity.device_id_keypair.is_null(False))
            | (Entity.server_state.is_null(False))
        )

        total_entities = entities_query.count()

        if total_entities == 0:
            logger.info("No entities with keypairs or server_state found.")
            return

        logger.info(f"Found {total_entities} entities to process.")
        logger.info(f"Processing in batches of {BATCH_SIZE}...")

        entity_ids = [entity.eid for entity in entities_query]

        with tqdm(
            total=len(entity_ids), desc="Rotating entity encryption", unit="entities"
        ) as pbar:
            for batch_ids in chunked(entity_ids, BATCH_SIZE):
                with Entity._meta.database.atomic():
                    batch_entities = Entity.select().where(Entity.eid.in_(batch_ids))

                    for entity in batch_entities:
                        fields_to_save = []

                        if entity.country_code:
                            try:
                                decrypted_data = decode_and_decrypt(entity.country_code)
                                entity.country_code = encrypt_and_encode(decrypted_data)
                                fields_to_save.append("country_code")
                            except Exception as e:
                                error_msg = f"Error rotating country_code: {e}"
                                logger.error(f"Entity {entity.eid} - {error_msg}")
                                rotation_errors["entities"].append(
                                    {
                                        "eid": entity.eid,
                                        "field": "country_code",
                                        "reason": str(e),
                                    }
                                )

                        if entity.publish_keypair:
                            try:
                                decrypted_data = decrypt_data(entity.publish_keypair)
                                entity.publish_keypair = encrypt_data(decrypted_data)
                                fields_to_save.append("publish_keypair")
                            except Exception as e:
                                error_msg = f"Error rotating publish_keypair: {e}"
                                logger.error(f"Entity {entity.eid} - {error_msg}")
                                rotation_errors["entities"].append(
                                    {
                                        "eid": entity.eid,
                                        "field": "publish_keypair",
                                        "reason": str(e),
                                    }
                                )

                        if entity.device_id_keypair:
                            try:
                                decrypted_data = decrypt_data(entity.device_id_keypair)
                                entity.device_id_keypair = encrypt_data(decrypted_data)
                                fields_to_save.append("device_id_keypair")
                            except Exception as e:
                                error_msg = f"Error rotating device_id_keypair: {e}"
                                logger.error(f"Entity {entity.eid} - {error_msg}")
                                rotation_errors["entities"].append(
                                    {
                                        "eid": entity.eid,
                                        "field": "device_id_keypair",
                                        "reason": str(e),
                                    }
                                )

                        if entity.server_state:
                            try:
                                decrypted_data = decrypt_data(entity.server_state)
                                entity.server_state = encrypt_data(decrypted_data)
                                fields_to_save.append("server_state")
                            except Exception as e:
                                error_msg = f"Error rotating server_state: {e}"
                                logger.error(f"Entity {entity.eid} - {error_msg}")
                                rotation_errors["entities"].append(
                                    {
                                        "eid": entity.eid,
                                        "field": "server_state",
                                        "reason": str(e),
                                    }
                                )

                        if fields_to_save:
                            try:
                                entity.save(only=fields_to_save)
                            except Exception as e:
                                error_msg = f"Error saving entity: {e}"
                                logger.error(f"Entity {entity.eid} - {error_msg}")
                                rotation_errors["entities"].append(
                                    {
                                        "eid": entity.eid,
                                        "field": "save_operation",
                                        "reason": str(e),
                                    }
                                )

                        pbar.update(1)


def rotate_token_encryption():
    """Rotate encryption for token data."""

    with Token._meta.database.connection_context():
        tokens_query = Token.select().where(
            (Token.account_identifier.is_null(False))
            | (Token.account_tokens.is_null(False))
        )

        total_tokens = tokens_query.count()

        if total_tokens == 0:
            logger.info("No tokens with token_data found.")
            return

        logger.info(f"Found {total_tokens} tokens to process.")
        logger.info(f"Processing in batches of {BATCH_SIZE}...")

        token_ids = [token.id for token in tokens_query]

        with tqdm(
            total=len(token_ids), desc="Rotating token encryption", unit="tokens"
        ) as pbar:
            for batch_ids in chunked(token_ids, BATCH_SIZE):
                with Token._meta.database.atomic():
                    batch_tokens = Token.select().where(Token.id.in_(batch_ids))

                    for token in batch_tokens:
                        fields_to_save = []

                        if token.account_tokens:
                            try:
                                decrypted_data = decode_and_decrypt(
                                    token.account_tokens
                                )
                                token.account_tokens = encrypt_and_encode(
                                    decrypted_data
                                )
                                fields_to_save.append("account_tokens")
                            except Exception as e:
                                error_msg = f"Error rotating account_tokens: {e}"
                                logger.error(f"Token {token.id} - {error_msg}")
                                rotation_errors["tokens"].append(
                                    {
                                        "id": token.id,
                                        "field": "account_tokens",
                                        "reason": str(e),
                                    }
                                )

                        if token.account_identifier:
                            try:
                                decrypted_data = decode_and_decrypt(
                                    token.account_identifier
                                )
                                token.account_identifier = encrypt_and_encode(
                                    decrypted_data
                                )
                                fields_to_save.append("account_identifier")
                            except Exception as e:
                                error_msg = f"Error rotating account_identifier: {e}"
                                logger.error(f"Token {token.id} - {error_msg}")
                                rotation_errors["tokens"].append(
                                    {
                                        "id": token.id,
                                        "field": "account_identifier",
                                        "reason": str(e),
                                    }
                                )

                        if fields_to_save:
                            try:
                                token.save(only=fields_to_save)
                            except Exception as e:
                                error_msg = f"Error saving token: {e}"
                                logger.error(f"Token {token.id} - {error_msg}")
                                rotation_errors["tokens"].append(
                                    {
                                        "id": token.id,
                                        "field": "save_operation",
                                        "reason": str(e),
                                    }
                                )

                        pbar.update(1)


def rotate_static_keypair_encryption():
    """Rotate encryption for static keypairs."""

    with StaticKeypairs._meta.database.connection_context():
        keypairs_query = StaticKeypairs.select().where(
            StaticKeypairs.keypair_bytes.is_null(False)
        )

        total_keypairs = keypairs_query.count()

        if total_keypairs == 0:
            logger.info("No static keypairs found.")
            return

        logger.info(f"Found {total_keypairs} static keypairs to process.")
        logger.info(f"Processing in batches of {BATCH_SIZE}...")

        keypair_ids = [keypair.id for keypair in keypairs_query]

        with tqdm(
            total=len(keypair_ids),
            desc="Rotating static keypair encryption",
            unit="keypairs",
        ) as pbar:
            for batch_ids in chunked(keypair_ids, BATCH_SIZE):
                with StaticKeypairs._meta.database.atomic():
                    batch_keypairs = StaticKeypairs.select().where(
                        StaticKeypairs.id.in_(batch_ids)
                    )

                    for keypair in batch_keypairs:
                        try:
                            decrypted_data = decrypt_data(keypair.keypair_bytes)
                            keypair.keypair_bytes = encrypt_data(decrypted_data)

                            keypair.save(only=["keypair_bytes"])
                        except Exception as e:
                            error_msg = f"Error rotating encryption: {e}"
                            logger.error(f"Static keypair {keypair.id} - {error_msg}")
                            rotation_errors["static_keypairs"].append(
                                {
                                    "id": keypair.id,
                                    "field": "keypair_bytes",
                                    "reason": str(e),
                                }
                            )

                        pbar.update(1)


def print_rotation_report():
    """Print comprehensive rotation error report."""
    print("\n" + "=" * 80)
    print("ENCRYPTION ROTATION REPORT")
    print("=" * 80)

    total_errors = (
        len(rotation_errors["entities"])
        + len(rotation_errors["tokens"])
        + len(rotation_errors["static_keypairs"])
    )

    if total_errors == 0:
        print("\n✓ All records rotated successfully with no errors!\n")
        print("=" * 80)
        return

    print(f"\n⚠ Total Errors: {total_errors}\n")

    if rotation_errors["entities"]:
        print(f"\nENTITY ERRORS ({len(rotation_errors['entities'])})")
        print("-" * 80)
        for idx, error in enumerate(rotation_errors["entities"], 1):
            print(f"{idx}. EID: {error['eid']}")
            print(f"   Field: {error['field']}")
            print(f"   Reason: {error['reason']}\n")

    if rotation_errors["tokens"]:
        print(f"\nTOKEN ERRORS ({len(rotation_errors['tokens'])})")
        print("-" * 80)
        for idx, error in enumerate(rotation_errors["tokens"], 1):
            print(f"{idx}. Token ID: {error['id']}")
            print(f"   Field: {error['field']}")
            print(f"   Reason: {error['reason']}\n")

    if rotation_errors["static_keypairs"]:
        print(f"\nSTATIC KEYPAIR ERRORS ({len(rotation_errors['static_keypairs'])})")
        print("-" * 80)
        for idx, error in enumerate(rotation_errors["static_keypairs"], 1):
            print(f"{idx}. Keypair ID: {error['id']}")
            print(f"   Field: {error['field']}")
            print(f"   Reason: {error['reason']}\n")

    print("=" * 80 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rotate encryption of all encrypted data in the vault."
    )

    parser.add_argument(
        "--no-decode",
        action="store_true",
        help="Use load_key instead of load_and_decode_key for decryption",
    )

    args = parser.parse_args()
    NO_DECODE = args.no_decode

    if NO_DECODE:
        logger.info("Using load_key for decryption")
    else:
        logger.info("Using load_and_decode_key for decryption")

    rotate_entity_encryption()
    rotate_token_encryption()
    rotate_static_keypair_encryption()
    logger.info("Encryption rotation completed.")
    print_rotation_report()
