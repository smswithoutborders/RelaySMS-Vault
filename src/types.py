# SPDX-License-Identifier: GPL-3.0-only
"""Common type definitions for the application."""

from enum import Enum


class ContactType(Enum):
    """Contact types for OTP delivery."""

    PHONE = "phone_number"
    EMAIL = "email_address"


class OTPAction(Enum):
    """OTP action types."""

    AUTH = "auth"
    SIGNUP = "signup"
    RESET_PASSWORD = "reset_password"


class EntityOrigin(Enum):
    """
    Enum representing how an entity was created.
    """

    WEB = "web"
    BRIDGE = "bridge"


class StatsEventType(Enum):
    """Stats event types."""

    AUTH = "auth"
    SIGNUP = "signup"
    RESET_PASSWORD = "reset_password"
    DELETE_ACCOUNT = "delete_account"


class StatsEventStage(Enum):
    """Stats event stages."""

    INITIATE = "initiate"
    COMPLETE = "complete"
