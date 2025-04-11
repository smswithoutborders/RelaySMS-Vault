"""
Entity's Tokens Controllers
"""

from playhouse.shortcuts import model_to_dict
from peewee import DoesNotExist
from src.db_models import Token
from src.utils import remove_none_values
from base_logger import get_logger

logger = get_logger(__name__)
database = Token._meta.database


def create_entity_token(
    entity,
    platform,
    account_identifier_hash,
    account_identifier,
    account_tokens,
    **kwargs,
):
    """
    Create a new token associated with an entity.

    Args:
        entity (Entity): The entity associated with the token.
        platform (str): The platform name.
        account_identifier_hash (str): The hashed account identifier.
        account_identifier (str): The account identifier.
        account_tokens (str): The token data.
        **kwargs: Additional fields.

    Returns:
        Token: The created token object.
    """
    with database.atomic():
        token_data = {
            "eid": entity,
            "platform": platform,
            "account_identifier_hash": account_identifier_hash,
            "account_identifier": account_identifier,
            "account_tokens": account_tokens,
            **kwargs,
        }
        logger.debug("Creating a new token...")
        token = Token.create(**token_data)
    return token


def fetch_entity_tokens(
    entity, fetch_all=False, fields=None, return_json=False, **search_criteria
):
    """
    Fetch tokens associated with the given entity.

    Args:
        entity (Entity): The entity associated with the tokens.
        fetch_all (bool, optional): If True, fetch all tokens
            associated with the entity regardless of search criteria.
            If False (default), fetch tokens based on search criteria.
        fields (list[str] or None, optional): Optional list of fields to select.
        return_json (bool, optional): If True, return the results as a list of dicts.
            If False (default), return the results as a list of token objects.
        **search_criteria: Additional keyword arguments representing the fields
            and their values to search for.

    Returns:
        list[dict] or list[Token]: A list of token objects or a list of dictionaries
            containing token data if return_json is True.
    """
    logger.debug("Fetching tokens for the specified entity...")
    results = []

    with database.atomic():
        query = entity.tokens

        if not fetch_all and search_criteria:
            conditions = [
                getattr(Token, key) == value
                for key, value in search_criteria.items()
                if value is not None
            ]
            query = query.where(*conditions)
            logger.debug("Applying search criteria to the query...")

        if fields:
            select = (getattr(Token, key) for key in fields)
            query = query.select(*select)
            logger.debug("Applying field selection to the query...")

        tokens = list(query.execute())
        logger.debug("Executing token fetch query...")

    if return_json:
        for token in tokens:
            token_dict = model_to_dict(token)
            results.append(token_dict)
        return remove_none_values(results)

    return tokens


def find_token(**search_criteria):
    """
    Find a single token based on search criteria.

    Args:
        **search_criteria: Additional keyword arguments representing the fields
            and their values to search for.

    Returns:
        Token or None: The token object if found, otherwise None.
    """
    logger.debug("Finding a token based on the specified criteria...")
    with database.connection_context():
        try:
            token = Token.get(**search_criteria)
            logger.debug("Token is found...")
            return token
        except DoesNotExist:
            logger.debug("Token is not found...")
            return None


def update_entity_tokens(entity, update_fields, **search_criteria):
    """
    Update tokens associated with the given entity based on search criteria.

    Args:
        entity (Entity): The entity associated with the tokens.
        update_fields (dict): A dictionary of fields to update with their new values.
        **search_criteria: Additional keyword arguments representing the fields
            and their values to search for.

    Returns:
        int: The number of rows updated.
    """
    logger.debug("Updating tokens for the specified entity...")
    with database.atomic():
        query = Token.update(**update_fields).where(Token.eid == entity)

        if search_criteria:
            conditions = [
                (getattr(Token, key) == value)
                for key, value in search_criteria.items()
                if value is not None
            ]
            if conditions:
                query = query.where(*conditions)
                logger.debug("Applying search criteria: %s", search_criteria)

        rows_updated = query.execute()
        logger.debug("Number of tokens updated: %s", rows_updated)

    return rows_updated
