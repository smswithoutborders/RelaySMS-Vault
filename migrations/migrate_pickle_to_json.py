# SPDX-License-Identifier: GPL-3.0-only
"""Migrate server_state from pickle to JSON serialization."""

import argparse

from peewee import chunked
from smswithoutborders_libsig.protocols import States
from tqdm import tqdm

from base_logger import get_logger
from src.db_models import Entity
from src.utils import decrypt_data, encrypt_data

logger = get_logger("vault.migrate_pickle_to_json")

BATCH_SIZE = 500

migration_errors = []


def migrate_server_state(encrypted_state: bytes) -> bytes:
    """Migrate encrypted server_state from pickle to JSON.

    Args:
        encrypted_state: Encrypted pickle-serialized state.

    Returns:
        Encrypted JSON-serialized state.
    """
    decrypted_pickle = decrypt_data(encrypted_state)
    state = States.deserialize(decrypted_pickle)
    json_serialized = state.serialize_json()

    # Verify migration
    verified_state = States.deserialize_json(json_serialized)
    if state != verified_state:
        raise ValueError("Migration verification failed")

    return encrypt_data(json_serialized)


def run_migration():
    """Migrate all server_state records from pickle to JSON."""

    with Entity._meta.database.connection_context():
        entities_query = Entity.select().where(Entity.server_state.is_null(False))
        total_entities = entities_query.count()

        if total_entities == 0:
            logger.info("No entities with server_state found.")
            return

        logger.info(f"Found {total_entities} entities to migrate.")
        logger.info(f"Processing in batches of {BATCH_SIZE}...")

        entity_ids = [entity.eid for entity in entities_query]

        with tqdm(
            total=len(entity_ids), desc="Migrating server_state", unit="entities"
        ) as pbar:
            for batch_ids in chunked(entity_ids, BATCH_SIZE):
                with Entity._meta.database.atomic():
                    batch_entities = Entity.select().where(Entity.eid.in_(batch_ids))

                    for entity in batch_entities:
                        try:
                            migrated_state = migrate_server_state(entity.server_state)
                            entity.server_state = migrated_state
                            entity.save(only=["server_state"])
                        except Exception as e:
                            logger.error(f"Entity {entity.eid} - Migration failed: {e}")
                            migration_errors.append(
                                {"eid": entity.eid, "reason": str(e)}
                            )

                        pbar.update(1)


def print_migration_report():
    """Print migration summary."""
    print("\n" + "=" * 80)
    print("MIGRATION REPORT")
    print("=" * 80)

    if not migration_errors:
        print("\n✓ All records migrated successfully!\n")
        print("=" * 80)
        return

    print(f"\n⚠ Total Errors: {len(migration_errors)}\n")
    print("-" * 80)
    for idx, error in enumerate(migration_errors, 1):
        print(f"{idx}. EID: {error['eid']}")
        print(f"   Reason: {error['reason']}\n")

    print("=" * 80 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Migrate server_state from pickle to JSON serialization."
    )
    args = parser.parse_args()

    logger.info("Starting migration from pickle to JSON...")
    run_migration()
    logger.info("Migration completed.")
    print_migration_report()
