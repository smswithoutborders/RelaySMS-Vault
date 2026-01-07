# SPDX-License-Identifier: GPL-3.0-only
"""Delete Entity Token gRPC Internal Service Implementation"""

import grpc

from base_logger import get_logger
from protos.v1 import vault_pb2
from src.tokens import fetch_entity_tokens
from src.utils import get_supported_platforms, hash_data

logger = get_logger(__name__)

SUPPORTED_PLATFORMS = get_supported_platforms()


def DeleteEntityToken(self, request, context):
    """Handles deleting tokens for an entity"""

    response = vault_pb2.DeleteEntityTokenResponse

    try:
        invalid_fields_response = self.handle_request_field_validation(
            context,
            request,
            response,
            ["long_lived_token", "platform", "account_identifier"],
        )
        if invalid_fields_response:
            return invalid_fields_response

        entity_obj, llt_error_response = self.handle_long_lived_token_validation(
            request, context, response
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

        existing_tokens = fetch_entity_tokens(
            entity=entity_obj,
            account_identifier_hash=account_identifier_hash,
            platform=request.platform,
        )

        if not existing_tokens:
            return self.handle_create_grpc_error_response(
                context,
                response,
                "No token found with account "
                f"identifier {request.account_identifier} for {request.platform}",
                grpc.StatusCode.NOT_FOUND,
            )

        existing_tokens[0].delete_instance()

        logger.info("Successfully deleted token.")

        return response(
            message="Token deleted successfully.",
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
