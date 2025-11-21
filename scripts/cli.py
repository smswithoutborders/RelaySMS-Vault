"""Vault CLI"""

import sys
import argparse
from src.crypto import generate_hmac
from src.entity import find_entity, create_entity
from src.utils import (
    get_configs,
    generate_eid,
    encrypt_and_encode,
    clear_keystore,
    load_key,
)
from base_logger import get_logger

logger = get_logger("vault.cli")

HASHING_KEY = load_key(get_configs("HMAC_KEY_FILE"), 32)
DUMMY_PHONENUMBERS = get_configs(
    "DUMMY_PHONENUMBERS", default_value="+237123456789"
).split(",")
DUMMY_PASSWORD = get_configs("DUMMY_PASSWORD", default_value="dummy_password")


def create(phonenumber, password, country_code):
    """Create an Entity (for dummy entities only)."""

    if phonenumber not in DUMMY_PHONENUMBERS:
        logger.error("Entity phone number must be a dummy phone number.")
        sys.exit(1)

    phone_number_hash = generate_hmac(HASHING_KEY, phonenumber)
    entity_obj = find_entity(phone_number_hash=phone_number_hash)

    if entity_obj:
        logger.info("Entity with this phone number already exists.")
        sys.exit(0)

    eid = generate_eid(phone_number_hash)
    password_hash = generate_hmac(HASHING_KEY, password)
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
