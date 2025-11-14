# SPDX-License-Identifier: GPL-3.0-only
"""Create Bridge Entity gRPC Internal Service Implementation"""

import base64

import grpc

import vault_pb2
from base_logger import get_logger
from src import signups
from src.db_models import StaticKeypairs
from src.entity import create_entity, find_entity
from src.otp_service import create_inapp_otp, send_otp, verify_otp
from src.utils import (
    clear_keystore,
    decrypt_and_deserialize,
    encrypt_and_encode,
    generate_eid,
    generate_keypair_and_public_key,
    get_configs,
    hash_data,
    serialize_and_encrypt,
)

logger = get_logger(__name__)

MOCK_OTP = (get_configs("MOCK_OTP", default_value="true") or "").lower() == "true"
DEFAULT_LANGUAGE = "en"


def CreateBridgeEntity(self, request, context):
    """Handles the creation of a bridge entity."""

    response = vault_pb2.CreateBridgeEntityResponse

    def complete_creation(entity_obj):
        success, message = verify_otp(
            request.phone_number,
            request.ownership_proof_response,
        )
        if not success:
            return self.handle_create_grpc_error_response(
                context,
                response,
                message,
                grpc.StatusCode.UNAUTHENTICATED,
            )

        entity_obj.is_bridge_enabled = True
        entity_obj.save(only=["is_bridge_enabled"])

        return response(message="Bridge Entity Created Successfully", success=True)

    def initiate_creation(phone_number_hash, eid, entity_obj=None):
        if request.server_pub_key_identifier:
            return handle_bridge_entity_creation(phone_number_hash, eid, entity_obj)

        invalid_fields_response = self.handle_request_field_validation(
            context,
            request,
            response,
            ["country_code", "client_publish_pub_key"],
        )
        if invalid_fields_response:
            return invalid_fields_response

        country_code_ciphertext_b64 = encrypt_and_encode(request.country_code)

        clear_keystore(eid)
        entity_publish_keypair, entity_publish_pub_key = (
            generate_keypair_and_public_key(eid, "publish")
        )

        if entity_obj:
            entity_obj.client_publish_pub_key = request.client_publish_pub_key
            entity_obj.publish_keypair = serialize_and_encrypt(entity_publish_keypair)
            entity_obj.server_state = None
            entity_obj.save(
                only=["client_publish_pub_key", "publish_keypair", "server_state"]
            )
        else:
            fields = {
                "eid": eid,
                "phone_number_hash": phone_number_hash,
                "password_hash": None,
                "country_code": country_code_ciphertext_b64,
                "client_publish_pub_key": request.client_publish_pub_key,
                "publish_keypair": serialize_and_encrypt(entity_publish_keypair),
                "is_bridge_enabled": False,
            }

            create_entity(**fields)

        if MOCK_OTP:
            otp_code = "123456"
        else:
            _, otp_result = create_inapp_otp(request.phone_number)
            otp_code, _ = otp_result

        logger.debug(
            "Length of entity_publish_pub_key: %s bytes",
            len(entity_publish_pub_key),
        )

        auth_phrase = bytes([len(entity_publish_pub_key)]) + entity_publish_pub_key

        logger.debug("Total length of auth_phrase: %s bytes", len(auth_phrase))

        message_body = (
            f"RelaySMS Please paste this entire message in your RelaySMS app \n"
            f"{otp_code} {base64.b64encode(auth_phrase).decode('utf-8')}"
        )

        message_length = len(message_body)
        sms_count = (message_length // 140) + (1 if message_length % 140 > 0 else 0)
        logger.debug(
            "Message Length: %s characters (SMS count: %s)",
            message_length,
            sms_count,
        )

        success, message, _ = send_otp(request.phone_number, message_body=message_body)

        if not success:
            return self.handle_create_grpc_error_response(
                context,
                response,
                message,
                grpc.StatusCode.INVALID_ARGUMENT,
            )

        signups.create_record(
            country_code=request.country_code,
            source="bridges",
            auth_method="phone_number",
        )

        return response(success=True, message=message_body if MOCK_OTP else message)

    # This is for bridge_server payload version >=1
    def handle_bridge_entity_creation(phone_number_hash, eid, entity_obj=None):
        invalid_fields_response = self.handle_request_field_validation(
            context,
            request,
            response,
            ["country_code", "client_publish_pub_key", "server_pub_key_identifier"],
        )
        if invalid_fields_response:
            return invalid_fields_response

        server_publish_keypair = StaticKeypairs.get_keypair(
            request.server_pub_key_identifier,
            request.server_pub_key_version or "v1",
        )

        if not server_publish_keypair or server_publish_keypair.status != "active":
            status = "not found" if not server_publish_keypair else "not active"
            return self.handle_create_grpc_error_response(
                context,
                response,
                "The server public key identifier "
                f"'{request.server_pub_key_identifier}' for version "
                f"{request.server_pub_key_version} is {status}.",
                grpc.StatusCode.NOT_FOUND,
            )

        server_publish_keypair_obj = decrypt_and_deserialize(
            server_publish_keypair.keypair_bytes
        )
        if entity_obj:
            new_server_pub_key = server_publish_keypair_obj.get_public_key()
            current_server_pub_key = (
                decrypt_and_deserialize(entity_obj.publish_keypair).get_public_key()
                if entity_obj.publish_keypair
                else None
            )

            if (new_server_pub_key != current_server_pub_key) or (
                request.client_publish_pub_key != entity_obj.client_publish_pub_key
            ):
                logger.info(
                    "Detected new public keys. Overwriting existing keys for the entity."
                )
                clear_keystore(eid)
                entity_obj.client_publish_pub_key = request.client_publish_pub_key
                entity_obj.publish_keypair = serialize_and_encrypt(
                    server_publish_keypair_obj
                )
                entity_obj.server_state = None
                entity_obj.is_bridge_enabled = True
                entity_obj.language = request.language or DEFAULT_LANGUAGE
                entity_obj.save(
                    only=[
                        "client_publish_pub_key",
                        "publish_keypair",
                        "server_state",
                        "is_bridge_enabled",
                        "language",
                    ]
                )
                logger.info("Successfully reauthenticated entity.")
                return response(
                    success=True, message="Successfully reauthenticated entity."
                )

            if entity_obj.language != request.language:
                entity_obj.language = request.language or DEFAULT_LANGUAGE
                entity_obj.save(only=["language"])

            logger.info("Successfully verified entity.")
            return response(success=True, message="Successfully verified entity.")

        create_entity(
            eid=eid,
            phone_number_hash=phone_number_hash,
            password_hash=None,
            country_code=encrypt_and_encode(request.country_code),
            client_publish_pub_key=request.client_publish_pub_key,
            publish_keypair=serialize_and_encrypt(server_publish_keypair_obj),
            is_bridge_enabled=True,
            language=request.language or DEFAULT_LANGUAGE,
        )
        signups.create_record(
            country_code=request.country_code,
            source="bridges",
            auth_method="phone_number",
        )

        logger.info("Successfully created entity.")
        return response(success=True, message="Successfully created entity.")

    try:
        invalid_fields_response = self.handle_request_field_validation(
            context,
            request,
            response,
            ["country_code", "phone_number"],
        )
        if invalid_fields_response:
            return invalid_fields_response

        phone_number_hash = hash_data(request.phone_number)
        entity_obj = find_entity(phone_number_hash=phone_number_hash)

        eid = generate_eid(phone_number_hash)

        if request.ownership_proof_response:
            return complete_creation(entity_obj)

        return initiate_creation(phone_number_hash, eid, entity_obj)

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
