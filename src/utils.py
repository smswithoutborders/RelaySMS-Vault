"""Utitlies Module."""

import os
import uuid
import base64
import re
import json
from datetime import datetime, timedelta
from functools import wraps

from cryptography.hazmat.primitives.asymmetric import x25519 as x25519_core
import mysql.connector
from peewee import DatabaseError
from smswithoutborders_libsig.keypairs import x25519

from src.crypto import encrypt_aes, decrypt_aes
from base_logger import get_logger

SUPPORTED_PLATFORM_FILE_PATH = "platforms.json"

logger = get_logger(__name__)


def load_key(filepath, key_length):
    """
    Load a key from a file.

    This function reads the first line from the specified
    file and returns the specified number of characters
    from that line, encoded as bytes.

    Args:
        filepath (str): The path to the file containing the key.
        key_length (int): The number of characters to load from the first line.

    Returns:
        bytes: The specified number of characters from the first line in the file
            encoded as bytes.

    Raises:
        FileNotFoundError: If the file does not exist at the specified filepath.
        Exception: If an unexpected error occurs during file reading.
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


def create_tables(models):
    """
    Creates tables for the given models if they don't
        exist in their specified database.

    Args:
        models(list): A list of Peewee Model classes.
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


def ensure_database_exists(host, user, password, database_name):
    """
    Decorator that ensures a MySQL database exists before executing a function.

    Args:
        host (str): The host address of the MySQL server.
        user (str): The username for connecting to the MySQL server.
        password (str): The password for connecting to the MySQL server.
        database_name (str): The name of the database to ensure existence.

    Returns:
        function: Decorated function.
    """

    def decorator(func):
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


def get_configs(config_name, strict=False, default_value=None):
    """
    Retrieves the value of a configuration from the environment variables.

    Args:
        config_name (str): The name of the configuration to retrieve.
        strict (bool): If True, raises an error if the configuration
            is not found. Default is False.
        default_value (str): The default value to return if the configuration
            is not found and strict is False. Default is None.

    Returns:
        str: The value of the configuration, or default_value if not found and s
            trict is False.

    Raises:
        KeyError: If the configuration is not found and strict is True.
        ValueError: If the configuration value is empty and strict is True.
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


def set_configs(config_name, config_value) -> None:
    """
    Sets the value of a configuration in the environment variables.

    Args:
        config_name (str): The name of the configuration to set.
        config_value (str or bool): The value of the configuration to set.

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


def generate_eid(phone_number_hash, namespace=uuid.NAMESPACE_DNS):
    """
    Generate a UUID based on a phone number hash using UUID5.

    Parameters:
    - phone_number_hash (str): The hash of the phone number.
    - namespace (uuid.UUID): The namespace identifier. Defaults to uuid.NAMESPACE_DNS.

    Returns:
    - str: The hexadecimal representation of the generated UUID.
    """
    return uuid.uuid5(namespace, phone_number_hash).hex


def generate_keypair_and_public_key(eid, keystore_name):
    """
    Generate keypair and public key.

    Args:
        eid (str): The unique identifier for the entity.
        keystore_name (str): The name of the keystore file where the keypair
            will be stored.

    Returns:
        tuple: A tuple containing:
            - keypair_obj: The keypair object generated by the x25519 algorithm.
            - peer_pub_key: The public key associated with the generated keypair.
    """
    keystore_path = get_configs("KEYSTORE_PATH")
    file_path = os.path.join(keystore_path, f"{eid}_{keystore_name}.db")
    keypair_obj = x25519(file_path)
    peer_pub_key = keypair_obj.init()
    return keypair_obj, peer_pub_key


def load_keypair_object(keypair):
    """
    Deserialize a serialized x25519 keypair object from bytes.

    Args:
        keypair (bytes): Serialized x25519 keypair object.

    Returns:
        x25519: Deserialized x25519 keypair object.
    """
    return x25519().deserialize(keypair)


def get_shared_key(keystore_path, pnt_keystore, secret_key, peer_pub_key):
    """
    Generate a shared key.

    Args:
        keystore_path (str): Path to the keystore file.
        pnt_keystore (str): The keystore pointer.
        secret_key (bytes): Secret key used for the keypair.
        peer_pub_key (bytes): Public key of the peer to generate the shared key with.

    Returns:
        bytes: The generated shared key.
    """
    keypair_obj = x25519(keystore_path, pnt_keystore, secret_key)
    shared_key = keypair_obj.agree(peer_pub_key)
    return shared_key


def encrypt_and_encode(plaintext):
    """
    Encrypt and encode plaintext.

    Args:
        plaintext (str): Plaintext to encrypt and encode.

    Returns:
        str: Base64 encoded ciphertext.
    """
    encryption_key = load_key(get_configs("SHARED_KEY"), 32)

    return base64.b64encode(
        encrypt_aes(
            encryption_key,
            plaintext,
        )
    ).decode("utf-8")


def decrypt_and_decode(encoded_ciphertext):
    """
    Decode and decrypt encoded ciphertext.

    Args:
        encoded_ciphertext (str): Base64 encoded ciphertext to decode and decrypt.

    Returns:
        str: Decrypted plaintext.
    """
    encryption_key = load_key(get_configs("SHARED_KEY"), 32)

    ciphertext = base64.b64decode(encoded_ciphertext)
    return decrypt_aes(encryption_key, ciphertext)


def convert_to_fernet_key(secret_key):
    """
    Converts a secret key to a Fernet key.

    Args:
        secret_key (bytes): The secret key (must be 32 bytes long).

    Returns:
        bytes: The base64-encoded Fernet key.
    """
    if len(secret_key) != 32:
        raise ValueError("Secret key must be 32 bytes long")

    return base64.urlsafe_b64encode(secret_key)


def is_valid_x25519_public_key(encoded_key):
    """
    Validates an X25519 public key encoded in base64.

    Args:
        encoded_key (bytes): The base64-encoded public key to validate.

    Returns:
        tuple[bool, str]: A tuple where the first element is a boolean i
            ndicating whether the key is valid, and the second element is an
            error message if the key is invalid, or None if the key
            is valid.
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


def remove_none_values(values):
    """
    Removes None values from a list of dictionaries.

    Args:
        values (list): A list of dictionaries.

    Returns:
        list: A new list of dictionaries where None values have been removed.

    Example:
        values = [
            {"a": 1, "b": None, "c": 3},
            {"a": None, "b": 2, "c": 3},
            {"a": 1, "b": 2, "c": None}
        ]
        filtered_values = remove_none_values(values)
        # Output: [{'a': 1, 'c': 3}, {'b': 2, 'c': 3}, {'a': 1, 'b': 2}]
    """
    return [{k: v for k, v in value.items() if v is not None} for value in values]


def clear_keystore(eid, keystore_name=None):
    """
    Delete keystore files based on eid and optionally a specific keystore name.

    Args:
        eid (str): The unique identifier for the keystore files.
        keystore_name (str, optional): The specific keystore name to delete. If not provided,
            it will delete all related keystore files.
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


def load_platforms_from_file(file_path):
    """
    Load platform data from a JSON file.

    Args:
        file_path (str): The path to the JSON file containing platform data.

    Returns:
        dict: A dictionary containing platform data.
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


def get_supported_platforms():
    """Get supported platforms"""
    platform_details = load_platforms_from_file(SUPPORTED_PLATFORM_FILE_PATH)
    return tuple(platform["name"] for platform in platform_details)


def get_platforms_by_protocol_type(protocol_type):
    """
    Get all platform names with the given protocol_type.

    Args:
        protocol_type (str): The protocol type to filter platforms by.

    Returns:
        tuple: A tuple of platform names matching the protocol_type.
    """
    platform_details = load_platforms_from_file(SUPPORTED_PLATFORM_FILE_PATH)
    return tuple(
        platform["name"]
        for platform in platform_details
        if platform.get("protocol_type") == protocol_type
    )


def validate_metrics_args(
    start_date: str = None,
    end_date: str = None,
    top=None,
    page=None,
    page_size=None,
):
    """
    Validates arguments for metrics endpoints.

    Args:
        start_date (str): Start date in "YYYY-MM-DD" format.
        end_date (str): End date in "YYYY-MM-DD" format.
        top (int, optional): Maximum number of results to return.
        page (int, optional): Page number for pagination.
        page_size (int, optional): Number of records per page.

    Raises:
        ValueError: If any of the validations fail.
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
    """
    Validates and parses a date string.

    Args:
        date_str (str): The date string to validate.
        field_name (str): Name of the field (for error messages).

    Returns:
        datetime: Parsed datetime object.
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


def filter_dict(original_dict, keys_to_remove=None, include_only=None):
    """
    Filter a dictionary by either removing specified keys or including only specified keys.

    Args:
        original_dict (dict): The dictionary to filter.
        keys_to_remove (iterable, optional): A collection of keys to be removed from the dictionary.
        include_only (iterable, optional): A collection of keys to include in the filtered
            dictionary, in the specified order.

    Returns:
        dict: A new dictionary filtered according to the specified criteria.

    Raises:
        ValueError: If both `keys_to_remove` and `include_only` are provided.
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
