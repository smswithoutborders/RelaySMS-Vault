# SPDX-License-Identifier: GPL-3.0-only
"""Utilities module."""

import base64
import json
import os
import re
import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import mysql.connector
from cryptography.hazmat.primitives.asymmetric import x25519 as x25519_core
from peewee import DatabaseError
from smswithoutborders_libsig.keypairs import x25519

from base_logger import get_logger
from src.crypto import decrypt_aes, encrypt_aes, generate_hmac, verify_hmac

SUPPORTED_PLATFORM_FILE_PATH = "platforms.json"

logger = get_logger(__name__)


def load_key(filepath: str, key_length: int) -> bytes:
    """Load key from file and return first key_length characters as bytes.

    Args:
        filepath: Path to the key file.
        key_length: Number of characters to load.

    Returns:
        Key bytes.

    Raises:
        FileNotFoundError: If file doesn't exist.
        Exception: If unexpected error occurs.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            key = f.readline().strip()[:key_length]
            return key.encode("utf-8")
    except FileNotFoundError:
        logger.error(
            "Key file not found at %s. Please check the configuration.",
            filepath,
        )
        raise
    except Exception as e:
        logger.critical("An unexpected error occurred while loading the key: %s", e)
        raise


def load_and_decode_key(filepath: str, key_length: int) -> bytes:
    """Load and Base64-decode key from file."""

    try:
        with open(filepath, "rb") as f:
            encoded = f.readline().strip()

        try:
            key = base64.b64decode(encoded, validate=True)
        except Exception:
            logger.error("Invalid Base64 in key file: %s", filepath)
            raise

        if len(key) != key_length:
            logger.error(
                "Invalid key length in file %s: expected %d bytes, got %d bytes.",
                filepath,
                key_length,
                len(key),
            )
            raise ValueError("Invalid key length.")

        return key

    except FileNotFoundError:
        logger.error("Key file not found at %s.", filepath)
        raise
    except Exception as e:
        logger.error("Failed to load and decode key: %s", e)
        raise


def create_tables(models: List[Any]) -> None:
    """Create tables for given Peewee models if they don't exist.

    Args:
        models: List of Peewee Model classes.
    """
    if not models:
        logger.warning("No models provided for table creation.")
        return

    try:
        databases = {}
        for model in models:
            database = model._meta.database
            if database not in databases:
                databases[database] = []
            databases[database].append(model)

        for database, db_models in databases.items():
            with database.atomic():
                existing_tables = set(database.get_tables())
                tables_to_create = [
                    model
                    for model in db_models
                    if model._meta.table_name not in existing_tables
                ]

                if tables_to_create:
                    database.create_tables(tables_to_create)
                    logger.info(
                        "Created tables: %s",
                        [model._meta.table_name for model in tables_to_create],
                    )
                else:
                    logger.debug("No new tables to create.")

    except DatabaseError as e:
        logger.error("An error occurred while creating tables: %s", e)


def ensure_database_exists(
    host: str, user: str, password: str, database_name: str
) -> Callable:
    """Decorator to ensure MySQL database exists before function execution.

    Args:
        host: MySQL server host address.
        user: MySQL username.
        password: MySQL password.
        database_name: Database name.

    Returns:
        Decorated function.
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                with mysql.connector.connect(
                    host=host,
                    user=user,
                    password=password,
                    charset="utf8mb4",
                    collation="utf8mb4_unicode_ci",
                ) as connection:
                    with connection.cursor() as cursor:
                        sql = "CREATE DATABASE IF NOT EXISTS " + database_name
                        cursor.execute(sql)

            except mysql.connector.Error as error:
                logger.error("Failed to create database: %s", error)

            return func(*args, **kwargs)

        return wrapper

    return decorator


def get_configs(config_name: str, strict: bool = False, default_value: str = "") -> str:
    """Retrieve configuration from environment variables.

    Args:
        config_name: Configuration name.
        strict: If True, raises error if not found.
        default_value: Default value if not found and not strict.

    Returns:
        Configuration value.

    Raises:
        KeyError: If strict is True and config not found.
        ValueError: If strict is True and value is empty.
    """
    try:
        value = (
            os.environ[config_name]
            if strict
            else os.environ.get(config_name) or default_value
        )
        if strict and (value is None or value.strip() == ""):
            raise ValueError(f"Configuration '{config_name}' is missing or empty.")
        return value
    except KeyError as error:
        logger.error(
            "Configuration '%s' not found in environment variables: %s",
            config_name,
            error,
        )
        raise
    except ValueError as error:
        logger.error("Configuration '%s' is empty: %s", config_name, error)
        raise


def get_bool_config(key: str, default_value: bool = False) -> bool:
    """Retrieve config value as boolean.

    Args:
        key: Configuration key.
        default_value: Default if missing or invalid.

    Returns:
        Boolean value.
    """
    value = get_configs(key)
    if value is None:
        return default_value

    value = value.strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    elif value in {"false", "0", "no", "off"}:
        return False
    return default_value


def get_list_config(key: str, default_value: Optional[List[str]] = None) -> List[str]:
    """Retrieve config value as list of strings.

    Args:
        key: Configuration key.
        default_value: Default if missing.

    Returns:
        List of strings.
    """
    value = get_configs(key)
    if not value:
        return default_value or []

    items = value.strip("[]")
    return [c.strip().strip("'\"").upper() for c in items.split(",") if c.strip()]


def set_configs(config_name: str, config_value: Any) -> None:
    """Set environment variable configuration.

    Args:
        config_name: Configuration name.
        config_value: Configuration value.

    Raises:
        ValueError: If config_name is empty.
    """
    if not config_name:
        error_message = (
            f"Cannot set configuration. Invalid config_name '{config_name}'."
        )
        logger.error(error_message)
        raise ValueError(error_message)

    try:
        if isinstance(config_value, bool):
            config_value = str(config_value).lower()
        os.environ[config_name] = str(config_value)
    except Exception as error:
        logger.error("Failed to set configuration '%s': %s", config_name, error)
        raise


def generate_eid(
    identifier_hash: str, namespace: uuid.UUID = uuid.NAMESPACE_DNS
) -> str:
    """Generate UUID5 from identifier hash.

    Args:
        identifier_hash: Hash of identifier (phone/email).
        namespace: UUID namespace.

    Returns:
        Hex representation of generated UUID.
    """
    return uuid.uuid5(namespace, identifier_hash).hex


def generate_keypair_and_public_key(eid: str, keystore_name: str) -> Tuple[Any, bytes]:
    """Generate X25519 keypair and public key.

    Args:
        eid: Unique entity identifier.
        keystore_name: Keystore file name.

    Returns:
        Tuple of (keypair_object, public_key).
    """
    keystore_path = get_configs("KEYSTORE_PATH")
    file_path = os.path.join(keystore_path, f"{eid}_{keystore_name}.db")
    keypair_obj = x25519(file_path)
    peer_pub_key = keypair_obj.init()
    return keypair_obj, peer_pub_key


def deserialize_keypair(keypair: bytes) -> Any:
    """Deserialize X25519 keypair from bytes.

    Args:
        keypair: Serialized keypair bytes.

    Returns:
        Deserialized x25519 keypair object.
    """
    return x25519().deserialize(keypair)


def get_shared_key(
    keystore_path: str, pnt_keystore: str, secret_key: bytes, peer_pub_key: bytes
) -> bytes:
    """Generate shared key using X25519 key agreement.

    Args:
        keystore_path: Path to keystore file.
        pnt_keystore: Keystore pointer.
        secret_key: Secret key for keypair.
        peer_pub_key: Peer's public key.

    Returns:
        Generated shared key bytes.
    """
    keypair_obj = x25519(keystore_path, pnt_keystore, secret_key)
    shared_key = keypair_obj.agree(peer_pub_key)
    return shared_key


def encrypt_and_encode(plaintext: str) -> str:
    """Encrypt and Base64-encode plaintext.

    Args:
        plaintext: Plaintext to encrypt.

    Returns:
        Base64-encoded ciphertext.
    """
    encryption_key = load_and_decode_key(
        get_configs("DATA_ENCRYPTION_KEY_PRIMARY_FILE"), 32
    )

    return base64.b64encode(
        encrypt_aes(
            encryption_key,
            plaintext,
        )
    ).decode("utf-8")


def decode_and_decrypt(encoded_ciphertext: str) -> str:
    """Decode and decrypt Base64-encoded ciphertext.

    Args:
        encoded_ciphertext: Base64-encoded ciphertext.

    Returns:
        Decrypted plaintext.
    """
    encryption_key = load_and_decode_key(
        get_configs("DATA_ENCRYPTION_KEY_PRIMARY_FILE"), 32
    )

    ciphertext = base64.b64decode(encoded_ciphertext)
    return decrypt_aes(encryption_key, ciphertext)


def encrypt_data(data_bytes: bytes) -> bytes:
    """Encrypt data for database storage.

    Args:
        data_bytes: Serialized data bytes.

    Returns:
        Encrypted data bytes.
    """
    encryption_key = load_and_decode_key(
        get_configs("DATA_ENCRYPTION_KEY_PRIMARY_FILE", strict=True), 32
    )
    return encrypt_aes(encryption_key, data_bytes, is_bytes=True)


def decrypt_data(encrypted_data: bytes) -> bytes:
    """Decrypt data from database.

    Args:
        encrypted_data: Encrypted data bytes.

    Returns:
        Decrypted data bytes.
    """
    encryption_key = load_and_decode_key(
        get_configs("DATA_ENCRYPTION_KEY_PRIMARY_FILE", strict=True), 32
    )
    return decrypt_aes(encryption_key, encrypted_data, is_bytes=True)


def decrypt_and_deserialize(encrypted_keypair: bytes) -> Optional[Any]:
    """Decrypt and deserialize keypair.

    Args:
        encrypted_keypair_blob: Encrypted keypair from database.

    Returns:
        X25519 keypair object or None if blob is None.
    """
    if not encrypted_keypair:
        return None

    decrypted_bytes = decrypt_data(encrypted_keypair)
    return deserialize_keypair(decrypted_bytes)


def serialize_and_encrypt(data_obj: Any) -> bytes:
    """Serialize and encrypt data object.

    Args:
        data_obj: Object with serialize() method.

    Returns:
        Encrypted serialized bytes.
    """
    serialized_bytes = data_obj.serialize()
    return encrypt_data(serialized_bytes)


def hash_data(data: str) -> str:
    """Generate HMAC hash of data.

    Args:
        data: Data to hash.

    Returns:
        HMAC hash string.
    """

    hashing_key = load_key(get_configs("HMAC_KEY_FILE", strict=True), 32)
    return generate_hmac(hashing_key, data)


def verify_hash(data: str, expected_hash: str) -> bool:
    """Verify HMAC hash of data.

    Args:
        data: Data to verify.
        expected_hash: Expected HMAC hash.

    Returns:
        Boolean indicating if hash matches.
    """
    hashing_key = load_key(get_configs("HMAC_KEY_FILE", strict=True), 32)
    return verify_hmac(hashing_key, data, expected_hash)


def convert_to_fernet_key(secret_key: bytes) -> bytes:
    """Convert 32-byte secret key to Fernet key.

    Args:
        secret_key: 32-byte secret key.

    Returns:
        Base64-encoded Fernet key.

    Raises:
        ValueError: If secret_key is not 32 bytes.
    """
    if len(secret_key) != 32:
        raise ValueError("Secret key must be 32 bytes long")

    return base64.urlsafe_b64encode(secret_key)


def is_valid_x25519_public_key(encoded_key: bytes) -> Tuple[bool, Optional[str]]:
    """Validate Base64-encoded X25519 public key.

    Args:
        encoded_key: Base64-encoded public key.

    Returns:
        Tuple of (is_valid, error_message).
    """
    try:
        decoded_key = base64.b64decode(encoded_key)
    except (TypeError, ValueError) as err:
        logger.exception("Base64 decoding error: %s", err)
        return False, "Invalid base64 encoding"

    try:
        x25519_core.X25519PublicKey.from_public_bytes(decoded_key)
        return True, None
    except ValueError as err:
        logger.exception("X25519 public key validation error: %s", err)
        return False, f"Invalid X25519 public key: {err}"


def remove_none_values(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove None values from list of dictionaries.

    Args:
        values: List of dictionaries.

    Returns:
        List with None values removed from each dict.
    """
    return [{k: v for k, v in value.items() if v is not None} for value in values]


def clear_keystore(eid: str, keystore_name: Optional[str] = None) -> None:
    """Delete keystore files by eid and optional keystore name.

    Args:
        eid: Unique identifier for keystore files.
        keystore_name: Specific keystore name to delete, or None for all.
    """
    file_suffixes = [keystore_name] if keystore_name else ["publish", "device_id"]
    keystore_path = get_configs("KEYSTORE_PATH")

    for suffix in file_suffixes:
        file_name = f"{eid}_{suffix}.db"
        file_path = os.path.join(keystore_path, file_name)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                logger.debug("Successfully removed: %s", file_name.replace(eid, "****"))
            else:
                logger.debug("File not found: %s", file_name.replace(eid, "****"))
        except Exception as e:
            logger.error(
                "Error removing file %s: %s", file_name.replace(eid, "****"), e
            )


def load_platforms_from_file(file_path: str) -> List[Dict[str, Any]]:
    """Load platform details from JSON file.

    Args:
        file_path: Path to platforms JSON file.

    Returns:
        List of platform dictionaries.

    Raises:
        FileNotFoundError: If file doesn't exist.
        json.JSONDecodeError: If file has invalid JSON.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            platforms_data = json.load(file)
        return platforms_data
    except FileNotFoundError:
        logger.error("Error: File '%s' not found.", file_path)
        return {}
    except json.JSONDecodeError as e:
        logger.error("Error decoding JSON from '%s': %s", file_path, e)
        return {}


def get_supported_platforms() -> Tuple[str, ...]:
    """Get all supported platform names.

    Returns:
        Tuple of platform names.
    """
    platform_details = load_platforms_from_file(SUPPORTED_PLATFORM_FILE_PATH)
    return tuple(platform["name"] for platform in platform_details)


def get_platforms_by_protocol_type(protocol_type: str) -> Tuple[str, ...]:
    """Get platform names by protocol type.

    Args:
        protocol_type: Protocol type to filter by.

    Returns:
        Tuple of matching platform names.
    """
    platform_details = load_platforms_from_file(SUPPORTED_PLATFORM_FILE_PATH)
    return tuple(
        platform["name"]
        for platform in platform_details
        if platform.get("protocol_type") == protocol_type
    )


def validate_metrics_args(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    top: Optional[int] = None,
    page: Optional[int] = None,
    page_size: Optional[int] = None,
) -> None:
    """Validate metrics endpoint arguments.

    Args:
        start_date: Start date in "YYYY-MM-DD" format.
        end_date: End date in "YYYY-MM-DD" format.
        top: Maximum number of results.
        page: Page number for pagination.
        page_size: Records per page.

    Raises:
        ValueError: If validation fails.
    """
    if start_date is None:
        start_date = datetime.strftime(datetime.now() - timedelta(days=30), "%Y-%m-%d")
    if end_date is None:
        end_date = datetime.strftime(datetime.now(), "%Y-%m-%d")

    date_pattern = r"^\d{4}-\d{2}-\d{2}$"
    if not re.match(date_pattern, start_date):
        raise ValueError(
            f"Invalid 'start_date' format: '{start_date}'. "
            "Please provide a date in the 'YYYY-MM-DD' format."
        )
    if not re.match(date_pattern, end_date):
        raise ValueError(
            f"Invalid 'start_date' format: '{end_date}'. "
            "Please provide a date in the 'YYYY-MM-DD' format."
        )

    start_dt = parse_date(start_date, "start_date")
    end_dt = parse_date(end_date, "end_date")

    if start_dt > end_dt:
        raise ValueError("'start_date' must be earlier than 'end_date'.")

    for arg, name in [(top, "top"), (page, "page"), (page_size, "page_size")]:
        if arg is not None:
            if not isinstance(arg, int):
                raise ValueError(f"'{name}' must be an integer: {arg}")
            if arg <= 0:
                raise ValueError(f"'{name}' must be a positive integer: {arg}")

    if top is not None and (page is not None or page_size is not None):
        raise ValueError("'top' cannot be used with 'page' or 'page_size'.")


def parse_date(date_str: str, field_name: str) -> datetime:
    """Validate and parse date string in YYYY-MM-DD format.

    Args:
        date_str: Date string to parse.
        field_name: Field name for error messages.

    Returns:
        Parsed datetime object.

    Raises:
        ValueError: If date format is invalid.
    """
    try:
        parsed_date = datetime.strptime(date_str, "%Y-%m-%d")
        return parsed_date
    except ValueError as e:
        error_message = str(e)

        if "unconverted data remains" in error_message:
            raise ValueError(
                f"Invalid '{field_name}': '{date_str}'. Format must be 'YYYY-MM-DD'."
            ) from e
        if "month must be in" in error_message:
            raise ValueError(
                f"Invalid '{field_name}': '{date_str}'. The month value is out of range (01-12)."
            ) from e
        if "day is out of range" in error_message:
            raise ValueError(
                f"Invalid '{field_name}': '{date_str}'. The day is out of range for "
                "the given month and year."
            ) from e
        if "does not match format" in error_message:
            raise ValueError(
                f"Invalid '{field_name}': '{date_str}'. Format must be 'YYYY-MM-DD'."
            ) from e

        raise ValueError(
            f"Invalid '{field_name}': '{date_str}'. {error_message}"
        ) from e


def filter_dict(
    original_dict: Dict[str, Any],
    keys_to_remove: Optional[Iterable[str]] = None,
    include_only: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Filter dictionary by removing or including specified keys.

    Args:
        original_dict: Dictionary to filter.
        keys_to_remove: Keys to remove.
        include_only: Keys to include (in specified order).

    Returns:
        Filtered dictionary.

    Raises:
        ValueError: If both keys_to_remove and include_only are provided.
    """
    if keys_to_remove and include_only:
        raise ValueError("Cannot specify both 'keys_to_remove' and 'include_only'.")

    if include_only is not None:
        return {key: original_dict[key] for key in include_only if key in original_dict}

    if keys_to_remove is not None:
        new_dict = original_dict.copy()
        for key in keys_to_remove:
            new_dict.pop(key, None)
        return new_dict

    return original_dict
