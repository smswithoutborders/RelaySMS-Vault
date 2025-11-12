"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

from peewee import fn
from playhouse.shortcuts import chunked
from tqdm import tqdm
from src.utils import decode_and_decrypt
from src.db_models import Entity, Signups
from base_logger import get_logger

logger = get_logger("populate.signups")
database = Signups._meta.database


def process_batch(entities_batch):
    """
    Process a batch of entities by decrypting and preparing the data for insertion.

    Args:
        entities_batch (list): List of Entity objects.

    Returns:
        list: A list of dictionaries ready for insertion into the Signups table.
    """
    processed_batch = []
    for entity in entities_batch:
        processed_batch.append(
            {
                "country_code": decode_and_decrypt(entity.country_code),
                "source": entity.source,
                "date_created": entity.date_created,
            }
        )
    return processed_batch


def main():
    """Populate the Signups table using data from the Entities table."""

    entities_query = Entity.select(
        Entity.country_code,
        fn.IF(Entity.password_hash.is_null(), "bridges", "platforms").alias("source"),
        Entity.date_created,
    )

    total_entities = entities_query.count()
    batch_size = 500

    with database.atomic():
        for entities_batch in tqdm(
            chunked(entities_query.iterator(), batch_size),
            total=(total_entities // batch_size)
            + (1 if total_entities % batch_size > 0 else 0),
            desc="Processing and Inserting Signups",
        ):
            signups_to_insert = process_batch(entities_batch)
            Signups.insert_many(signups_to_insert).execute()

    logger.info("Signups table populated successfully.")


if __name__ == "__main__":
    main()
