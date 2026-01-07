# SPDX-License-Identifier: GPL-3.0-only
"""Update Password gRPC service implementation"""

import grpc

from base_logger import get_logger
from protos.v1 import vault_pb2
from src.password_rate_limit import (
    clear_rate_limit,
    is_rate_limited,
    register_password_attempt,
)
from src.password_validation import validate_password_strength
from src.utils import hash_password, verify_password

logger = get_logger(__name__)


def UpdateEntityPassword(self, request, context):
    """Handles changing an entity's password."""

    response = vault_pb2.UpdateEntityPasswordResponse

    def validate_fields():
        invalid_fields = self.handle_request_field_validation(
            context,
            request,
            response,
            ["long_lived_token", "current_password", "new_password"],
        )
        if invalid_fields:
            return invalid_fields

        invalid_password = validate_password_strength(request.new_password)
        if invalid_password:
            return self.handle_create_grpc_error_response(
                context,
                response,
                invalid_password,
                grpc.StatusCode.INVALID_ARGUMENT,
            )

        return None

    try:
        invalid_fields_response = validate_fields()
        if invalid_fields_response:
            return invalid_fields_response

        entity_obj, llt_error_response = self.handle_long_lived_token_validation(
            request, context, response
        )
        if llt_error_response:
            return llt_error_response

        if is_rate_limited(entity_obj.eid):
            return self.handle_create_grpc_error_response(
                context,
                response,
                "Too many password attempts. Please wait and try again later.",
                grpc.StatusCode.UNAVAILABLE,
            )

        register_password_attempt(entity_obj.eid)
        is_password_valid, _ = verify_password(
            request.current_password, entity_obj.password_hash
        )
        if not is_password_valid:
            return self.handle_create_grpc_error_response(
                context,
                response,
                "The current password you entered is incorrect. Please try again.",
                grpc.StatusCode.UNAUTHENTICATED,
            )

        clear_rate_limit(entity_obj.eid)
        new_password_hash = hash_password(request.new_password)

        entity_obj.password_hash = new_password_hash
        entity_obj.device_id = None
        entity_obj.client_publish_pub_key = None
        entity_obj.client_device_id_pub_key = None
        entity_obj.publish_keypair = None
        entity_obj.device_id_keypair = None
        entity_obj.save(
            only=[
                "password_hash",
                "device_id",
                "client_publish_pub_key",
                "client_device_id_pub_key",
                "publish_keypair",
                "device_id_keypair",
            ]
        )

        return response(message="Password updated successfully.", success=True)

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
