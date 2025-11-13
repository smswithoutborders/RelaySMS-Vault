# SPDX-License-Identifier: GPL-3.0-only
"""Authenticate Bridge Entity gRPC Internal Service Implementation"""

import grpc

import vault_pb2
from base_logger import get_logger
from src.entity import find_entity
from src.utils import hash_data

logger = get_logger(__name__)


def AuthenticateBridgeEntity(self, request, context):
    """Handles authenticating a bridge entity."""

    response = vault_pb2.AuthenticateBridgeEntityResponse

    try:
        invalid_fields_response = self.handle_request_field_validation(
            context,
            request,
            response,
            ["phone_number"],
        )
        if invalid_fields_response:
            return invalid_fields_response

        phone_number_hash = hash_data(request.phone_number)
        entity_obj = find_entity(phone_number_hash=phone_number_hash)

        if not entity_obj:
            return self.handle_create_grpc_error_response(
                context,
                response,
                "Bridge Entity with this phone number not found.",
                grpc.StatusCode.NOT_FOUND,
            )

        if not entity_obj.is_bridge_enabled:
            return self.handle_create_grpc_error_response(
                context,
                response,
                "Bridges are not enabled for Entity with this phone number.",
                grpc.StatusCode.UNAUTHENTICATED,
            )

        entity_language = request.language

        if entity_language and entity_obj.language != entity_language:
            entity_obj.language = entity_language
            entity_obj.save(only=["language"])

        return response(
            success=True,
            message="Authentication successful.",
            language=entity_obj.language,
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
