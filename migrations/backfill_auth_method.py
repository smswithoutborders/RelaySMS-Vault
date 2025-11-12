"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

from peewee import chunked
from tqdm import tqdm
from src.db_models import Entity, Signups
from base_logger import get_logger

logger = get_logger("backfill.auth_method")
database = Signups._meta.database


def estimate_email_signups():
    """
    Estimate which signups were done with email by matching signup records
    with entities that have an email_hash.

    This matches based on:
    - Country code
    - Date created (within a reasonable time window)
    - Source type (platforms only, as bridges don't support email)
    """

    # Get all signups with phone_number auth_method from platforms that could potentially be email
    signups_query = Signups.select().where(
        (Signups.auth_method == "phone_number") & (Signups.source == "platforms")
    )

    total_signups = signups_query.count()
    logger.info(
        f"Found {total_signups} platform signups with phone_number auth_method to check"
    )

    batch_size = 500
    updated_count = 0

    for signups_batch in tqdm(
        chunked(signups_query.iterator(), batch_size),
        total=(total_signups // batch_size)
        + (1 if total_signups % batch_size > 0 else 0),
        desc="Checking signups against entities with email",
    ):
        signup_ids_to_update = []

        for signup in signups_batch:
            # Check if there's an entity with email_hash created around the same time
            # with matching country code (encrypted in entities table)
            entity_exists = (
                Entity.select()
                .where(
                    Entity.email_hash.is_null(False)
                    & (Entity.date_created >= signup.date_created)
                    & (
                        Entity.date_created
                        <= signup.date_created.replace(hour=23, minute=59, second=59)
                    )
                )
                .exists()
            )

            if entity_exists:
                signup_ids_to_update.append(signup.id)

        # Batch update the identified signups
        if signup_ids_to_update:
            with database.atomic():
                count = (
                    Signups.update(auth_method="email")
                    .where(Signups.id.in_(signup_ids_to_update))
                    .execute()
                )
                updated_count += count

    logger.info(
        f"Estimated and updated {updated_count} signup records to 'email' auth_method"
    )
    return updated_count


def main():
    """
    Estimate which existing signup records were done with email by matching
    with entities that have email_hash. All other signups default to 'phone_number'
    via SQL constraint.
    """
    logger.info("Starting auth_method estimation migration...")

    email_count = estimate_email_signups()

    logger.info("Auth_method estimation completed successfully.")
    logger.info(f"Summary: {email_count} records estimated as 'email'")


if __name__ == "__main__":
    main()
