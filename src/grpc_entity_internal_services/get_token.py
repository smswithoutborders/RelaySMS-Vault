# SPDX-License-Identifier: GPL-3.0-only
"""Get Entity Access Token gRPC Internal Service Implementation"""

import grpc

from base_logger import get_logger
from protos.v1 import vault_pb2
from src.entity import find_entity
from src.tokens import fetch_entity_tokens
from src.utils import decode_and_decrypt, get_supported_platforms, hash_data

logger = get_logger(__name__)

SUPPORTED_PLATFORMS = get_supported_platforms()


def GetEntityAccessToken(self, request, context):
    """Handles getting an entity's access token."""

    response = vault_pb2.GetEntityAccessTokenResponse

    def validate_fields():
        return self.handle_request_field_validation(
            context,
            request,
            response,
            [
                ("device_id", "long_lived_token", "phone_number"),
                "platform",
                "account_identifier",
            ],
        )

    def fetch_tokens(entity_obj, account_identifier_hash):
        tokens = fetch_entity_tokens(
            entity=entity_obj,
            fields=["account_tokens"],
            return_json=True,
            platform=request.platform,
            account_identifier_hash=account_identifier_hash,
        )
        for token in tokens:
            for field in ["account_tokens"]:
                if field in token:
                    token[field] = decode_and_decrypt(token[field])

        logger.info("Successfully fetched tokens.")

        if not tokens:
            return self.handle_create_grpc_error_response(
                context,
                response,
                "No token found with account "
                f"identifier {request.account_identifier} for {request.platform}",
                grpc.StatusCode.NOT_FOUND,
            )

        return response(
            message="Successfully fetched tokens.",
            success=True,
            token=tokens[0]["account_tokens"],
        )

    try:
        invalid_fields_response = validate_fields()
        if invalid_fields_response:
            return invalid_fields_response

        if request.long_lived_token:
            entity_obj, llt_error_response = self.handle_long_lived_token_validation(
                request, context, response
            )
            if llt_error_response:
                return llt_error_response

        elif request.device_id:
            entity_obj = find_entity(device_id=request.device_id)
            if not entity_obj:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    f"Entity associated with device ID '{request.device_id}' not found. "
                    "Please log in again to obtain a valid device ID.",
                    grpc.StatusCode.UNAUTHENTICATED,
                )
        else:
            phone_number_hash = hash_data(request.phone_number)
            entity_obj = find_entity(phone_number_hash=phone_number_hash)
            if not entity_obj:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    f"Entity associated with phone number '{request.phone_number}' not found. "
                    "Please check your phone number and try again.",
                    grpc.StatusCode.UNAUTHENTICATED,
                )

        if request.platform.lower() not in SUPPORTED_PLATFORMS:
            raise NotImplementedError(
                f"The platform '{request.platform}' is currently not supported. "
                "Please contact the developers for more information on when "
                "this platform will be implemented."
            )

        account_identifier = request.account_identifier.strip()
        account_identifier_hash = hash_data(account_identifier)

        return fetch_tokens(entity_obj, account_identifier_hash)

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
