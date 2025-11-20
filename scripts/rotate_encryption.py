# SPDX-License-Identifier: GPL-3.0-only
"""Rotate encryption of all encrypted data in the vault."""

import base64
from tqdm import tqdm
from peewee import chunked
from src.db_models import Entity, Token, StaticKeypairs
from src.utils import encrypt_data, encrypt_and_encode, load_key, get_configs
from src.crypto import decrypt_aes
from base_logger import get_logger

logger = get_logger("vault.rotate_encryption")

BATCH_SIZE = 500


def decode_and_decrypt(encoded_ciphertext: str) -> str:
    """Decode and decrypt Base64-encoded ciphertext.

    Args:
        encoded_ciphertext: Base64-encoded ciphertext.

    Returns:
        Decrypted plaintext.
    """
    encryption_key = load_key(get_configs("SHARED_KEY"), 32)

    ciphertext = base64.b64decode(encoded_ciphertext)
    return decrypt_aes(encryption_key, ciphertext)


def decrypt_data(encrypted_data: bytes) -> bytes:
    """Decrypt data from database.

    Args:
        encrypted_data: Encrypted data bytes.

    Returns:
        Decrypted data bytes.
    """
    encryption_key = load_key(get_configs("SHARED_KEY", strict=True), 32)
    return decrypt_aes(encryption_key, encrypted_data, is_bytes=True)


def rotate_entity_encryption():
    """Rotate encryption for keypairs and server_state of all entities."""

    with Entity._meta.database.connection_context():
        entities_query = Entity.select().where(
            (Entity.publish_keypair.is_null(False))
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
                        try:
                            if entity.publish_keypair:
                                decrypted_data = decrypt_data(entity.publish_keypair)
                                entity.publish_keypair = encrypt_data(decrypted_data)

                            if entity.device_id_keypair:
                                decrypted_data = decrypt_data(entity.device_id_keypair)
                                entity.device_id_keypair = encrypt_data(decrypted_data)

                            if entity.server_state:
                                decrypted_data = decrypt_data(entity.server_state)
                                entity.server_state = encrypt_data(decrypted_data)

                            entity.save(
                                only=[
                                    "publish_keypair",
                                    "device_id_keypair",
                                    "server_state",
                                ]
                            )
                        except Exception as e:
                            logger.error(
                                f"Error rotating encryption for entity {entity.eid}: {e}"
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
                        try:
                            if token.account_tokens:
                                decrypted_data = decode_and_decrypt(
                                    token.account_tokens
                                )
                                token.account_tokens = encrypt_and_encode(
                                    decrypted_data
                                )

                            if token.account_identifier:
                                decrypted_data = decode_and_decrypt(
                                    token.account_identifier
                                )
                                token.account_identifier = encrypt_and_encode(
                                    decrypted_data
                                )

                            token.save(only=["account_tokens", "account_identifier"])
                        except Exception as e:
                            logger.error(
                                f"Error rotating encryption for token {token.id}: {e}"
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
                            logger.error(
                                f"Error rotating encryption for static keypair {keypair.id}: {e}"
                            )

                        pbar.update(1)


if __name__ == "__main__":
    rotate_entity_encryption()
    rotate_token_encryption()
    rotate_static_keypair_encryption()
    logger.info("Encryption rotation completed.")
