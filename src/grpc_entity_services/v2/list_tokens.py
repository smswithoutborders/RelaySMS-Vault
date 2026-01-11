# SPDX-License-Identifier: GPL-3.0-only
"""List Entity Stored Tokens gRPC service implementation."""

import json

import grpc

from base_logger import get_logger
from protos.v2 import vault_pb2
from src.tokens import fetch_entity_tokens, update_entity_tokens
from src.utils import (
    decode_and_decrypt,
    encrypt_and_encode,
    get_platforms_by_protocol_type,
    hash_data,
)

logger = get_logger(__name__)


def ListEntityStoredTokens(self, request, context):
    """Handles listing an entity's stored tokens."""

    response = vault_pb2.ListEntityStoredTokensResponse

    try:
        entity_obj, llt_error_response = self.handle_long_lived_token_v1_validation(
            context, response
        )
        if llt_error_response:
            return llt_error_response

        tokens = fetch_entity_tokens(
            entity=entity_obj,
            fetch_all=True,
            fields=["account_identifier", "platform", "account_tokens"],
            return_json=True,
        )

        oauth2_platforms = get_platforms_by_protocol_type("oauth2")
        fields_to_decrypt = ["account_identifier", "account_tokens"]

        for token in tokens:
            for field in fields_to_decrypt:
                if field in token:
                    token[field] = decode_and_decrypt(token[field])

            account_tokens = json.loads(token["account_tokens"])

            if (
                token["platform"] in oauth2_platforms
                and not account_tokens.get("access_token")
                and not account_tokens.get("refresh_token")
            ):
                token["is_stored_on_device"] = True

            if request.migrate_to_device and token["platform"] in oauth2_platforms:
                original_account_tokens = account_tokens.copy()
                token["account_tokens"] = {
                    key: account_tokens.pop(key, "")
                    for key in ["access_token", "refresh_token", "id_token"]
                }
                if account_tokens != original_account_tokens:
                    account_identifier_hash = hash_data(token.get("account_identifier"))

                    update_entity_tokens(
                        entity=entity_obj,
                        update_fields={
                            "account_tokens": encrypt_and_encode(
                                json.dumps(account_tokens)
                            )
                        },
                        platform=token.get("platform"),
                        account_identifier_hash=account_identifier_hash,
                    )
            else:
                token["account_tokens"] = {}

        logger.info("Successfully retrieved tokens.")
        return response(stored_tokens=tokens, message="Tokens retrieved successfully.")

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
