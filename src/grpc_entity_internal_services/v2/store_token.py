# SPDX-License-Identifier: GPL-3.0-only
"""Store Entity Token gRPC Internal Service Implementation"""

import grpc

from base_logger import get_logger
from protos.v2 import vault_pb2
from src.tokens import create_entity_token, find_token
from src.utils import encrypt_and_encode, get_supported_platforms, hash_data

logger = get_logger(__name__)

SUPPORTED_PLATFORMS = get_supported_platforms()


def StoreEntityToken(self, request, context):
    """Handles storing tokens for an entity"""

    response = vault_pb2.StoreEntityTokenResponse

    def check_existing_token(eid, account_identifier_hash):
        token = find_token(
            eid=eid,
            account_identifier_hash=account_identifier_hash,
            platform=request.platform,
        )

        if token:
            token.account_tokens = encrypt_and_encode(request.token)
            token.save(only=["account_tokens"])
            logger.info("Token overwritten successfully.")

            return response(
                message="Token stored successfully.",
                success=True,
            )

        return None

    try:
        invalid_fields_response = self.handle_request_field_validation(
            context, request, response, ["token", "platform", "account_identifier"]
        )
        if invalid_fields_response:
            return invalid_fields_response

        entity_obj, llt_error_response = self.handle_long_lived_token_v1_validation(
            context, response
        )
        if llt_error_response:
            return llt_error_response

        if request.platform.lower() not in SUPPORTED_PLATFORMS:
            raise NotImplementedError(
                f"The platform '{request.platform}' is currently not supported. "
                "Please contact the developers for more information on when "
                "this platform will be implemented."
            )

        account_identifier = request.account_identifier.strip()
        account_identifier_hash = hash_data(account_identifier)

        existing_token = check_existing_token(entity_obj.eid, account_identifier_hash)

        if existing_token:
            return existing_token

        new_token = {
            "entity": entity_obj,
            "platform": request.platform,
            "account_identifier_hash": account_identifier_hash,
            "account_identifier": encrypt_and_encode(request.account_identifier),
            "account_tokens": encrypt_and_encode(request.token),
        }
        create_entity_token(**new_token)
        logger.info("Successfully stored tokens.")

        return response(
            message="Token stored successfully.",
            success=True,
        )

    except NotImplementedError as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            str(e),
            grpc.StatusCode.UNIMPLEMENTED,
        )

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
