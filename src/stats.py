# SPDX-License-Identifier: GPL-3.0-only
"""Stats management functions."""

from base_logger import get_logger
from src.db_models import Stats
from src.types import ContactType, EntityOrigin, StatsEventStage, StatsEventType

logger = get_logger(__name__)
database = Stats._meta.database


def create(
    event_type: StatsEventType,
    country_code: str,
    identifier_type: ContactType,
    origin: EntityOrigin,
    event_stage: StatsEventStage,
):
    """Create a stats record."""
    with database.atomic():
        stat = Stats.create(
            event_type=event_type.value,
            country_code=country_code,
            identifier_type=identifier_type.value,
            origin=origin.value,
            event_stage=event_stage.value,
        )

    logger.info(
        f"Event: {event_type.value}, Stage: {event_stage.value} record created successfully"
    )
    return stat
