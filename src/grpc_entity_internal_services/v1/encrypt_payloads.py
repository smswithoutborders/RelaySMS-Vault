# SPDX-License-Identifier: GPL-3.0-only
"""Encrypt Payload gRPC Internal Service Implementation"""

import base64

import grpc

from base_logger import get_logger
from protos.v1 import vault_pb2
from src.entity import find_entity
from src.relaysms_payload import encode_relay_sms_payload, encrypt_payload
from src.utils import decrypt_data, hash_data, serialize_state_and_encrypt

logger = get_logger(__name__)


def EncryptPayload(self, request, context):
    """Handles encrypting payload"""

    response = vault_pb2.EncryptPayloadResponse

    def validate_fields():
        return self.handle_request_field_validation(
            context,
            request,
            response,
            [("device_id", "phone_number"), "payload_plaintext"],
        )

    def encrypt_message(entity_obj):
        decrypted_state = (
            decrypt_data(entity_obj.server_state) if entity_obj.server_state else None
        )

        header, content_ciphertext, state, encrypt_error = encrypt_payload(
            server_state=decrypted_state,
            client_publish_pub_key=base64.b64decode(entity_obj.client_publish_pub_key),
            content=request.payload_plaintext,
        )

        if encrypt_error:
            return None, self.handle_create_grpc_error_response(
                context,
                response,
                encrypt_error,
                grpc.StatusCode.INVALID_ARGUMENT,
                error_prefix="Error Encrypting Content",
                error_type="UNKNOWN",
            )

        return (header, content_ciphertext, state), None

    def encode_message(header, content_ciphertext, state):
        encoded_content, encode_error = encode_relay_sms_payload(
            header, content_ciphertext
        )

        if encode_error:
            return None, self.handle_create_grpc_error_response(
                context,
                response,
                encode_error,
                grpc.StatusCode.INVALID_ARGUMENT,
                error_prefix="Error Encoding Content",
                error_type="UNKNOWN",
            )

        entity_obj.server_state = serialize_state_and_encrypt(state)
        entity_obj.save(only=["server_state"])
        logger.info("Successfully encrypted payload.")

        return response(
            message="Successfully encrypted payload.",
            payload_ciphertext=encoded_content,
            success=True,
        )

    try:
        invalid_fields_response = validate_fields()
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

        encrypted_response, encrypting_error = encrypt_message(entity_obj)
        if encrypting_error:
            return encrypting_error

        header, content_ciphertext, state = encrypted_response

        return encode_message(header, content_ciphertext, state)

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
