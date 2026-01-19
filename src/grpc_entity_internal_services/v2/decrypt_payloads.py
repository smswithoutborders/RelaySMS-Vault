# SPDX-License-Identifier: GPL-3.0-only
"""Decrypt Payload gRPC Internal Service Implementation"""

import base64

import grpc

from base_logger import get_logger
from protos.v2 import vault_pb2
from src.entity import find_entity
from src.relaysms_payload import decode_relay_sms_payload, decrypt_payload
from src.utils import (
    decode_and_decrypt,
    decrypt_and_deserialize,
    decrypt_data,
    hash_data,
    serialize_state_and_encrypt,
)

logger = get_logger(__name__)


def DecryptPayload(self, request, context):
    """Handles decrypting relaysms payload"""

    response = vault_pb2.DecryptPayloadResponse

    def validate_fields():
        return self.handle_request_field_validation(
            context,
            request,
            response,
            [("device_id", "phone_number"), "payload_ciphertext"],
        )

    def decode_message():
        header, content_ciphertext, decode_error = decode_relay_sms_payload(
            request.payload_ciphertext
        )

        if decode_error:
            return None, self.handle_create_grpc_error_response(
                context,
                response,
                decode_error,
                grpc.StatusCode.INVALID_ARGUMENT,
                error_prefix="Error Decoding Content",
                error_type="UNKNOWN",
            )

        return (header, content_ciphertext), None

    def decrypt_message(entity_obj, header, content_ciphertext):
        is_v2_entity = bool(entity_obj.client_id_pub_key)

        decrypted_state = (
            decrypt_data(entity_obj.server_state) if entity_obj.server_state else None
        )

        if is_v2_entity:
            server_ratchet_keypair = decrypt_and_deserialize(
                entity_obj.server_ratchet_keypair
            )

            identity_key_success, server_identity_keypair = (
                self.get_server_identity_key(context, response)
            )
            if not identity_key_success:
                return server_identity_keypair

            if not decrypted_state:
                client_nonce = decrypt_data(entity_obj.client_nonce)
                server_nonce = decrypt_data(entity_obj.server_nonce)
            else:
                client_nonce = None
                server_nonce = None

            use_header_encryption = len(header) >= 60
            content_plaintext, state, decrypt_error = decrypt_payload(
                encrypted_content=content_ciphertext,
                ratchet_header=header,
                server_state=decrypted_state,
                server_identity_keypair=server_identity_keypair,
                server_ratchet_keypair=server_ratchet_keypair,
                server_nonce=server_nonce,
                client_ratchet_pub_key=entity_obj.client_ratchet_pub_key,
                client_header_pub_key=entity_obj.client_header_pub_key,
                client_next_header_pub_key=entity_obj.client_next_header_pub_key,
                client_nonce=client_nonce,
                client_id_pub_key=entity_obj.client_id_pub_key,
                use_header_encryption=use_header_encryption,
            )
        else:
            server_identity_keypair = decrypt_and_deserialize(
                entity_obj.publish_keypair
            )

            content_plaintext, state, decrypt_error = decrypt_payload(
                encrypted_content=content_ciphertext,
                ratchet_header=header,
                server_state=decrypted_state,
                server_identity_keypair=server_identity_keypair,
                associated_data=server_identity_keypair.get_public_key(),
            )

        if decrypt_error:
            return self.handle_create_grpc_error_response(
                context,
                response,
                decrypt_error,
                grpc.StatusCode.INVALID_ARGUMENT,
                error_prefix="Error Decrypting Content",
                error_type="UNKNOWN",
            )

        was_initialized = decrypted_state is None
        entity_obj.server_state = serialize_state_and_encrypt(state)

        if is_v2_entity and was_initialized:
            entity_obj.client_ratchet_pub_key = None
            entity_obj.client_header_pub_key = None
            entity_obj.client_next_header_pub_key = None
            entity_obj.client_nonce = None
            entity_obj.server_ratchet_keypair = None
            entity_obj.server_nonce = None
            entity_obj.save(
                only=[
                    "server_state",
                    "server_ratchet_keypair",
                    "server_nonce",
                    "client_ratchet_pub_key",
                    "client_header_pub_key",
                    "client_next_header_pub_key",
                    "client_nonce",
                ]
            )
            logger.debug(
                "Ephemeral ratchet keys and nonces deleted after state initialization."
            )
        else:
            entity_obj.save(only=["server_state"])

        logger.info("Successfully decrypted payload.")

        return response(
            message="Successfully decrypted payload",
            success=True,
            payload_plaintext=base64.b64encode(content_plaintext).decode("utf-8"),
            country_code=decode_and_decrypt(entity_obj.country_code),
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

        entity_id = entity_obj.eid
        entity_lock = self._get_entity_lock(entity_id)

        with entity_lock:
            logger.debug("Acquired lock for entity")
            entity_obj = find_entity(eid=entity_id)
            decoded_response, decoding_error = decode_message()
            if decoding_error:
                return decoding_error

            header, content_ciphertext = decoded_response

            result = decrypt_message(entity_obj, header, content_ciphertext)
            logger.debug("Released lock for entity")
            return result

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
