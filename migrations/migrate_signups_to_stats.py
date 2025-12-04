# SPDX-License-Identifier: GPL-3.0-only
"""Migration script to update signups and entities tables."""

from peewee import chunked
from tqdm import tqdm

from base_logger import get_logger
from src.db_models import Entity, Signups
from src.types import ContactType, EntityOrigin, StatsEventStage, StatsEventType

logger = get_logger("migrate.signups_to_stats")

BATCH_SIZE = 500

migration_errors = {"signups": [], "entities": []}


def migrate_signups_data():
    """Migrate data from old columns to new columns in signups table."""

    with Signups._meta.database.connection_context():
        signups_query = Signups.select()
        total_signups = signups_query.count()

        if total_signups == 0:
            logger.info("No signup records found.")
            return 0

        logger.info(f"Found {total_signups} signup records to migrate.")
        logger.info(f"Processing in batches of {BATCH_SIZE}...")

        signup_ids = [signup.id for signup in signups_query]
        updated_count = 0

        with tqdm(
            total=len(signup_ids), desc="Migrating signups data", unit="signups"
        ) as pbar:
            for batch_ids in chunked(signup_ids, BATCH_SIZE):
                try:
                    with Signups._meta.database.atomic():
                        batch_signups = Signups.select().where(
                            Signups.id.in_(batch_ids)
                        )

                        for signup in batch_signups:
                            identifier_type = (
                                ContactType.PHONE.value
                                if signup.auth_method == "phone_number"
                                else ContactType.EMAIL.value
                            )
                            origin = (
                                EntityOrigin.BRIDGE.value
                                if signup.source == "bridges"
                                else EntityOrigin.WEB.value
                            )
                            signup.identifier_type = identifier_type
                            signup.origin = origin
                            signup.event_type = StatsEventType.SIGNUP.value
                            signup.event_stage = StatsEventStage.INITIATE.value
                            signup.save(
                                only=[
                                    "identifier_type",
                                    "origin",
                                    "event_type",
                                    "event_stage",
                                ]
                            )
                            updated_count += 1

                        pbar.update(len(batch_ids))
                except Exception as e:
                    error_msg = f"Error migrating batch: {e}"
                    logger.error(error_msg)
                    migration_errors["signups"].append(
                        {"batch_ids": batch_ids, "reason": str(e)}
                    )
                    pbar.update(len(batch_ids))

        logger.info(f"Migrated {updated_count} signup records.")
        return updated_count


def migrate_entities_origin():
    """Set origin in entities table based on password_hash."""

    with Entity._meta.database.connection_context():
        bridges_count = 0
        platforms_count = 0

        try:
            with Entity._meta.database.atomic():
                bridges_count = (
                    Entity.update(origin=EntityOrigin.BRIDGE.value)
                    .where(Entity.password_hash.is_null())
                    .execute()
                )

                platforms_count = (
                    Entity.update(origin=EntityOrigin.WEB.value)
                    .where(Entity.password_hash.is_null(False))
                    .execute()
                )

            logger.info(
                f"Set origin for {bridges_count} {EntityOrigin.BRIDGE.value} entities."
            )
            logger.info(
                f"Set origin for {platforms_count} {EntityOrigin.WEB.value} entities."
            )
        except Exception as e:
            error_msg = f"Error migrating entities origin: {e}"
            logger.error(error_msg)
            migration_errors["entities"].append({"field": "origin", "reason": str(e)})

        return bridges_count + platforms_count


def print_migration_report():
    """Print comprehensive migration error report."""
    print("\n" + "=" * 80)
    print("SIGNUPS TO STATS MIGRATION REPORT")
    print("=" * 80)

    total_errors = len(migration_errors["signups"]) + len(migration_errors["entities"])

    if total_errors == 0:
        print("\n✓ All records migrated successfully with no errors!\n")
        print("=" * 80)
        return

    print(f"\n⚠ Total Errors: {total_errors}\n")

    if migration_errors["signups"]:
        print(f"\nSIGNUPS ERRORS ({len(migration_errors['signups'])})")
        print("-" * 80)
        for idx, error in enumerate(migration_errors["signups"], 1):
            print(f"{idx}. Batch IDs: {error['batch_ids']}")
            print(f"   Reason: {error['reason']}\n")

    if migration_errors["entities"]:
        print(f"\nENTITY ERRORS ({len(migration_errors['entities'])})")
        print("-" * 80)
        for idx, error in enumerate(migration_errors["entities"], 1):
            print(f"{idx}. Field: {error['field']}")
            print(f"   Reason: {error['reason']}\n")

    print("=" * 80 + "\n")


if __name__ == "__main__":
    logger.info("Starting signups to stats migration...")

    signups_migrated = migrate_signups_data()
    entities_migrated = migrate_entities_origin()

    logger.info("Migration completed.")
    logger.info(
        f"Summary: {signups_migrated} signups migrated, {entities_migrated} entities updated"
    )
    print_migration_report()
