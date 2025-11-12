"""
Script to clean and rehash account identifiers in tokens.
"""

import tqdm
from src.db_models import Token
from src.crypto import generate_hmac
from src.utils import decode_and_decrypt, encrypt_and_encode, load_key, get_configs
from base_logger import get_logger

HASHING_KEY = load_key(get_configs("HASHING_SALT"), 32)

logger = get_logger("clean.account.identifiers")


def fetch_tokens():
    """Fetch all tokens from the database."""
    return Token.select()


def process_token(token, pbar):
    """
    Process a single token to clean its account identifier if needed.

    Args:
        token: The token object to process.
        pbar: The tqdm progress bar to update.
    """
    try:
        account_identifier = decode_and_decrypt(token.account_identifier)
        account_identifier_hash = token.account_identifier

        clean_account_identifier = account_identifier.strip('"').strip()

        if account_identifier != clean_account_identifier:
            clean_account_identifier_hash = generate_hmac(
                HASHING_KEY, clean_account_identifier
            )
            logger.info(
                "Cleaning raw account identifier: '%r' to cleaned account identifier: '%r'",
                account_identifier,
                clean_account_identifier,
            )

            token.account_identifier = encrypt_and_encode(clean_account_identifier)
            if account_identifier_hash != clean_account_identifier_hash:
                token.account_identifier_hash = clean_account_identifier_hash

            token.save()

            return 1, int(account_identifier_hash != clean_account_identifier_hash)
    except Exception:
        logger.error(
            "Error cleaning account_identifier: %s",
            token.account_identifier,
            exc_info=True,
        )
    finally:
        pbar.update(1)
    return 0, 0


def main():
    """Main function to clean account identifiers in tokens."""
    tokens = fetch_tokens()
    total_tokens = tokens.count()
    total_clean_account_identifier = 0
    total_account_identifier_hash = 0

    with tqdm.tqdm(total=total_tokens, desc="Cleaning", unit="tokens") as pbar:
        for token in tokens.iterator():
            cleaned, rehashed = process_token(token, pbar)
            total_clean_account_identifier += cleaned
            total_account_identifier_hash += rehashed

    logger.info("Total Cleaned account identifiers: %s", total_clean_account_identifier)
    logger.info(
        "Total Cleaned account identifiers hash: %s", total_account_identifier_hash
    )


if __name__ == "__main__":
    main()
