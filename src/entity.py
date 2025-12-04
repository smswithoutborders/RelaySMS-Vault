# SPDX-License-Identifier: GPL-3.0-only
"""Entity management functions."""

from peewee import DoesNotExist

from base_logger import get_logger
from src.db_models import Entity

logger = get_logger(__name__)
database = Entity._meta.database


def create_entity(eid, password_hash, country_code, **kwargs):
    """
    Create a new entity.

    Args:
        eid (str): The ID of the entity.
        phone_number_hash (str): The hashed phone number of the entity.
        password_hash (str): The hashed password of the entity.
        **kwargs: Additional fields include username, publish_pub_key,
            device_id_pub_key.

    Returns:
        Entity: The created entity object.
    """
    with database.atomic():
        entity_data = {
            "eid": eid,
            "password_hash": password_hash,
            "country_code": country_code,
            **kwargs,
        }
        logger.debug("Creating a new entity...")
        entity = Entity.create(**entity_data)
    return entity


def find_entity(**search_criteria):
    """
    Find an entity by the given search criteria.

    Args:
        **search_criteria: Keyword arguments representing the fields
            and their values to search for.

    Returns:
        Entity or None: The found entity if exists, else None.
    """
    logger.debug("Finding an entity based on the specified criteria...")
    with database.connection_context():
        try:
            entity = Entity.get(**search_criteria)
            logger.debug("Entity is found...")
            return entity
        except DoesNotExist:
            logger.debug("Entity is not found...")
            return None


def fetch_all_entities(
    filters=None, date_range=None, truncate_by=None, return_json=False
):
    """
    Fetch all entities with optional filters, date range, and date truncation.

    Args:
        filters (dict, optional): A dictionary where the keys are field names
            and the values are the conditions/criteria to filter the entities by.
            Defaults to None.
        date_range (tuple, optional): A tuple containing (start_date, end_date) to
            filter the 'date_created' field by. Dates should be datetime objects.
        truncate_by (str, optional): Specify if the 'date_created' should be
            truncated by 'day' or 'month'. If provided, date filtering will apply
            to truncated dates.
        return_json (bool, optional): If True, return the results as a list of dicts.
            If False (default), return the results as a list of model instances.

    Returns:
        list: A list of all entities matching the filter criteria.
    """
    filters = filters or {}
    logger.debug(
        "Fetching all entities with filters: %s, date_range: %s, truncate_by: %s",
        filters,
        date_range,
        truncate_by,
    )

    with database.connection_context():
        query = Entity.select()
        conditions = []

        for field, value in filters.items():
            conditions.append(getattr(Entity, field) == value)

        if date_range:
            start_date, end_date = date_range
            if truncate_by == "day":
                conditions.append(
                    Entity.date_created.truncate("day").between(start_date, end_date)
                )
            elif truncate_by == "month":
                conditions.append(
                    Entity.date_created.truncate("month").between(start_date, end_date)
                )
            else:
                conditions.append(Entity.date_created.between(start_date, end_date))

        if conditions:
            query = query.where(*conditions)

        query = query.order_by(Entity.date_created.asc())

        total_records = query.count()
        logger.debug("Found %d entities", total_records)

        entities = list(query.dicts()) if return_json else list(query.execute())
        return entities
