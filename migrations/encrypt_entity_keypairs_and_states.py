"""
Migration script to encrypt entity keypairs and server states.
"""

import logging
from tqdm import tqdm
from peewee import chunked
from src.db_models import Entity
from src.utils import encrypt_data

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

database = Entity._meta.database
BATCH_SIZE = 500


def encrypt_entity_fields():
    """
    Encrypt keypairs and server_state for all entities that have unencrypted data.
    """
    with database.connection_context():
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

        encrypted_count = 0
        error_count = 0

        entity_ids = [entity.eid for entity in entities_query]

        with tqdm(
            total=len(entity_ids), desc="Encrypting entity data", unit="entities"
        ) as pbar:
            for batch_ids in chunked(entity_ids, BATCH_SIZE):
                with database.atomic():
                    batch_entities = Entity.select().where(Entity.eid.in_(batch_ids))

                    for entity in batch_entities:
                        try:
                            if entity.publish_keypair:
                                entity.publish_keypair = encrypt_data(
                                    entity.publish_keypair
                                )

                            if entity.device_id_keypair:
                                entity.device_id_keypair = encrypt_data(
                                    entity.device_id_keypair
                                )

                            if entity.server_state:
                                entity.server_state = encrypt_data(entity.server_state)

                            entity.save(
                                only=[
                                    "publish_keypair",
                                    "device_id_keypair",
                                    "server_state",
                                ]
                            )
                            encrypted_count += 1
                            logger.debug(
                                f"Successfully encrypted data for entity {entity.eid}"
                            )

                        except Exception as e:
                            error_count += 1
                            logger.error(
                                f"Error encrypting data for entity {entity.eid}: {e}",
                                exc_info=True,
                            )
                        finally:
                            pbar.update(1)

        logger.info("\nEncryption complete:")
        logger.info(f"  - Entities encrypted: {encrypted_count}")
        logger.info(f"  - Entities with errors: {error_count}")


def main():
    """Main function to run the migration."""
    logger.info("Starting encryption migration for entity keypairs and states...")

    try:
        encrypt_entity_fields()
        logger.info("Migration completed successfully!")
    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
