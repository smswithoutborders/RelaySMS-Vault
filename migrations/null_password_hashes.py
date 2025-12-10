# SPDX-License-Identifier: GPL-3.0-only
"""Migration script to null all password hashes in entities table."""

from peewee import chunked
from tqdm import tqdm

from base_logger import get_logger
from src.db_models import Entity

logger = get_logger("migrate.null_password_hashes")

BATCH_SIZE = 500

migration_errors = []


def null_all_passwords():
    """
    Set all password_hash fields to NULL in the entities table.

    This forces all users to reset their passwords, which will be hashed
    using the new Argon2id implementation.
    """
    logger.info("Starting migration to null all password hashes...")

    database = Entity._meta.database
    updated_count = 0

    try:
        with database.connection_context():
            entities_query = Entity.select()
            total_entities = entities_query.count()
            logger.info(f"Found {total_entities} entities to update")

            if total_entities == 0:
                logger.info("No entities found. Nothing to migrate.")
                return 0

            confirmation = input(
                f"\nThis will null password_hash for {total_entities} entities.\n"
                "All users will need to reset their passwords.\n"
                "Are you sure you want to proceed? (yes/no): "
            )

            if confirmation.lower() != "yes":
                logger.info("Migration cancelled by user.")
                return 0

            logger.info(f"Processing in batches of {BATCH_SIZE}...")
            entity_ids = [entity.eid for entity in entities_query]

            with tqdm(
                total=len(entity_ids), desc="Nulling passwords", unit="entities"
            ) as pbar:
                for batch_ids in chunked(entity_ids, BATCH_SIZE):
                    try:
                        with database.atomic():
                            count = (
                                Entity.update(password_hash=None)
                                .where(Entity.eid.in_(batch_ids))
                                .execute()
                            )
                            updated_count += count
                            pbar.update(len(batch_ids))
                    except Exception as e:
                        error_msg = f"Error nulling password batch: {e}"
                        logger.error(error_msg)
                        migration_errors.append(
                            {"batch_ids": batch_ids, "reason": str(e)}
                        )
                        pbar.update(len(batch_ids))

            logger.info(
                f"Successfully nulled password_hash for {updated_count} entities"
            )

    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)
        raise

    return updated_count


def print_migration_report():
    """Print comprehensive migration error report."""
    print("\n" + "=" * 80)
    print("PASSWORD HASH MIGRATION REPORT")
    print("=" * 80)

    total_errors = len(migration_errors)

    if total_errors == 0:
        print("\n✓ All records migrated successfully with no errors!\n")
        print("=" * 80)
        return

    print(f"\n⚠ Total Errors: {total_errors}\n")

    if migration_errors:
        print(f"\nENTITY ERRORS ({len(migration_errors)})")
        print("-" * 80)
        for idx, error in enumerate(migration_errors, 1):
            print(f"{idx}. Batch IDs: {error['batch_ids']}")
            print(f"   Reason: {error['reason']}\n")

    print("=" * 80 + "\n")


if __name__ == "__main__":
    logger.info("=" * 70)
    logger.info("Password Hash Migration Script")
    logger.info("This script will null all password_hash fields in entities table")
    logger.info("=" * 70)

    entities_updated = null_all_passwords()

    logger.info("Migration completed.")
    logger.info(f"Summary: {entities_updated} entities updated")
    logger.info("Users will need to reset their passwords on next login.")
    print_migration_report()
