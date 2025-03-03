"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import datetime
from enum import Enum
from peewee import (
    Model,
    CharField,
    TextField,
    DateTimeField,
    IntegerField,
    UUIDField,
    ForeignKeyField,
    BlobField,
    BooleanField,
    SQL,
)
from src.db import connect
from src.utils import create_tables, get_configs

database = connect()


class Entity(Model):
    """Model representing Entities Table."""

    eid = UUIDField(primary_key=True)
    phone_number_hash = CharField()
    password_hash = CharField(null=True)
    country_code = CharField()
    device_id = CharField(null=True)
    client_publish_pub_key = TextField(null=True)
    client_device_id_pub_key = TextField(null=True)
    publish_keypair = BlobField(null=True)
    device_id_keypair = BlobField(null=True)
    server_state = BlobField(null=True)
    is_bridge_enabled = BooleanField(default=True)
    language = CharField(null=True, constraints=[SQL("DEFAULT 'en'")])
    date_created = DateTimeField(default=datetime.datetime.now)

    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = "entities"
        indexes = (
            (("phone_number_hash",), True),
            (("device_id",), True),
        )


class OTPRateLimit(Model):
    """Model representing OTP Rate Limits Table."""

    phone_number = CharField()
    attempt_count = IntegerField(default=0)
    date_expires = DateTimeField(null=True)
    date_created = DateTimeField(default=datetime.datetime.now)

    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = "otp_rate_limit"
        indexes = ((("phone_number",), True),)


class Token(Model):
    """Model representing Tokens Table."""

    eid = ForeignKeyField(Entity, backref="tokens", column_name="eid")
    platform = CharField()
    account_identifier_hash = CharField()
    account_identifier = CharField()
    account_tokens = TextField()
    date_created = DateTimeField(default=datetime.datetime.now)

    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = "tokens"
        indexes = ((("platform", "account_identifier_hash", "eid"), True),)


class PasswordRateLimit(Model):
    """Model representing Password Rate Limits Table."""

    eid = ForeignKeyField(Entity, backref="password_rate_limit", column_name="eid")
    attempt_count = IntegerField(default=0)
    date_expires = DateTimeField(null=True)
    date_created = DateTimeField(default=datetime.datetime.now)

    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = "password_rate_limit"


class OTP(Model):
    """Model representing OTP Table."""

    phone_number = CharField()
    otp_code = CharField(max_length=10)
    attempt_count = IntegerField(default=0)
    date_expires = DateTimeField()
    is_verified = BooleanField(default=False)
    date_created = DateTimeField(default=datetime.datetime.now)

    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = "otp"
        indexes = (
            (("phone_number",), False),
            (("date_expires",), False),
        )

    def is_expired(self):
        """Check if the OTP is expired."""
        return datetime.datetime.now() > self.date_expires

    def reset_attempt_count(self):
        """Reset the attempt count for the OTP."""
        self.attempt_count = 0
        self.save()

    def increment_attempt_count(self):
        """Increment the attempt count for the OTP."""
        self.attempt_count += 1
        self.save()


class Signups(Model):
    """Model representing Signup Attempts."""

    country_code = CharField()
    source = CharField()
    date_created = DateTimeField(default=datetime.datetime.now)

    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = "signups"


class KeypairStatus(Enum):
    """
    Enum representing the status of a keypair.
    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


class StaticKeypairs(Model):
    """Model representing static x25519 keypairs."""

    kid = IntegerField()
    keypair_bytes = BlobField()
    status = CharField(
        choices=[(status.value, status.value) for status in KeypairStatus]
    )
    date_last_used = DateTimeField(null=True)
    date_created = DateTimeField(default=datetime.datetime.now)
    usage_count = IntegerField(default=0)
    version = CharField()

    class Meta:
        """Meta class to define database connection."""

        database = database
        table_name = "static_keypairs"
        indexes = ((("kid", "status", "version"), True),)

    @classmethod
    def create_keypair(cls, kid, keypair_bytes, status, version):
        """Creates and stores a new keypair safely."""
        if status not in KeypairStatus._value2member_map_:
            raise ValueError(
                f"Invalid status: {status}. Allowed: {[s.value for s in KeypairStatus]}"
            )
        with database.atomic():
            return cls.create(
                kid=kid, keypair_bytes=keypair_bytes, status=status, version=version
            )

    @classmethod
    def get_keypairs(cls, **criteria):
        """Retrieves keypairs based on dynamic filtering criteria."""
        query = cls.select()
        if criteria:
            for field, value in criteria.items():
                query = query.where(getattr(cls, field) == value)
        return list(query)

    @classmethod
    def get_keypair(cls, kid, version):
        """Retrieves a keypair by its ID and version."""
        keypair = cls.get_or_none(cls.kid == kid, cls.version == version)
        if keypair:
            with database.atomic():
                keypair.usage_count += 1
                keypair.date_last_used = datetime.datetime.now()
                keypair.save(only=["date_last_used", "usage_count"])
        return keypair

    @classmethod
    def keypair_exists(cls, kid):
        """Checks if a keypair exists by ID."""
        return cls.select().where(cls.kid == kid).exists()

    @classmethod
    def update_status(cls, kid, status):
        """Updates the status of a keypair safely."""
        if status not in KeypairStatus._value2member_map_:
            raise ValueError(
                f"Invalid status: {status}. Allowed: {[s.value for s in KeypairStatus]}"
            )
        with database.atomic():
            return cls.update(status=status).where(cls.kid == kid).execute()

    @classmethod
    def delete_keypair(cls, kid):
        """Deletes a keypair safely."""
        with database.atomic():
            keypair = cls.get_or_none(cls.kid == kid)
            if keypair:
                return keypair.delete_instance()
            return None


if get_configs("MODE", default_value="development") in ("production", "development"):
    create_tables(
        [Entity, OTPRateLimit, Token, PasswordRateLimit, OTP, Signups, StaticKeypairs]
    )
