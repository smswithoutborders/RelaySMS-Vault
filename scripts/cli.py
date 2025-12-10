# SPDX-License-Identifier: GPL-3.0-only
"""Vault CLI"""

import argparse
import sys

from base_logger import get_logger
from src.entity import create_entity, find_entity
from src.utils import (
    clear_keystore,
    encrypt_and_encode,
    generate_eid,
    get_configs,
    hash_data,
    hash_password,
)

logger = get_logger("vault.cli")

DUMMY_PHONENUMBERS = get_configs(
    "DUMMY_PHONENUMBERS", default_value="+237123456789"
).split(",")
DUMMY_PASSWORD = get_configs("DUMMY_PASSWORD", default_value="dummy_password")


def create(phonenumber, password, country_code):
    """Create an Entity (for dummy entities only)."""

    if phonenumber not in DUMMY_PHONENUMBERS:
        logger.error("Entity phone number must be a dummy phone number.")
        sys.exit(1)

    phone_number_hash = hash_data(phonenumber)
    entity_obj = find_entity(phone_number_hash=phone_number_hash)

    if entity_obj:
        if not entity_obj.password_hash:
            logger.info("Entity exists but has no password set.")
            entity_obj.password_hash = hash_password(password)
            entity_obj.save(only=["password_hash"])

        logger.info("Entity with this phone number already exists.")
        sys.exit(0)

    eid = generate_eid(phone_number_hash)
    password_hash = hash_password(password)
    country_code_ciphertext_b64 = encrypt_and_encode(country_code)

    clear_keystore(eid)

    fields = {
        "eid": eid,
        "phone_number_hash": phone_number_hash,
        "password_hash": password_hash,
        "country_code": country_code_ciphertext_b64,
    }

    create_entity(**fields)

    logger.info("Entity created successfully")
    sys.exit(0)


def main():
    """Entry function"""

    parser = argparse.ArgumentParser(description="Vault CLI")
    subparsers = parser.add_subparsers(dest="command", description="Expected commands")
    create_parser = subparsers.add_parser("create", help="Creates an entity.")
    create_parser.add_argument(
        "-n", "--phonenumber", type=str, help="Entity's phone number.", required=True
    )
    args = parser.parse_args()

    if args.command == "create":
        create(phonenumber=args.phonenumber, password=DUMMY_PASSWORD, country_code="CM")


if __name__ == "__main__":
    main()
