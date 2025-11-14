# SPDX-License-Identifier: GPL-3.0-only
"""Update Entity Token gRPC Internal Service Implementation"""

import grpc

import vault_pb2
from base_logger import get_logger
from src.entity import find_entity
from src.tokens import fetch_entity_tokens
from src.utils import encrypt_and_encode, hash_data

logger = get_logger(__name__)


def UpdateEntityToken(self, request, context):
    """Handles updating tokens for an entity"""

    response = vault_pb2.UpdateEntityTokenResponse

    try:
        invalid_fields_response = self.handle_request_field_validation(
            context,
            request,
            response,
            [
                ("device_id", "phone_number"),
                "token",
                "platform",
                "account_identifier",
            ],
        )
        if invalid_fields_response:
            return invalid_fields_response

        if request.device_id:
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

        existing_tokens[0].account_tokens = encrypt_and_encode(request.token)
        existing_tokens[0].save(only=["account_tokens"])
        logger.info("Successfully updated token.")

        return response(
            message="Token updated successfully.",
            success=True,
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
