# SPDX-License-Identifier: GPL-3.0-only
"""Create Entity gRPC service implementation."""

import base64

import grpc

import vault_pb2
from base_logger import get_logger
from src import signups
from src.device_id import compute_device_id
from src.entity import create_entity, find_entity
from src.long_lived_token import generate_llt
from src.otp_service import ContactType, OTPAction
from src.password_validation import validate_password_strength
from src.recaptcha import is_captcha_enabled
from src.utils import (
    clear_keystore,
    encrypt_and_encode,
    generate_eid,
    generate_keypair_and_public_key,
    hash_data,
    serialize_and_encrypt,
)

logger = get_logger(__name__)


def CreateEntity(self, request, context):
    """Handles the creation of an entity."""

    response = vault_pb2.CreateEntityResponse

    if hasattr(request, "phone_number"):
        request.phone_number = self.clean_phone_number(request.phone_number)

    def complete_creation():
        success, pow_response = self.handle_pow_verification(context, request, response)
        if not success:
            return pow_response

        identifier_type, identifier_value = self.get_identifier(request)
        identifier_hash = hash_data(identifier_value)
        eid = generate_eid(identifier_hash)
        password_hash = hash_data(request.password)
        country_code_ciphertext_b64 = encrypt_and_encode(request.country_code)

        clear_keystore(eid)
        entity_publish_keypair, entity_publish_pub_key = (
            generate_keypair_and_public_key(eid, "publish")
        )
        entity_device_id_keypair, entity_device_id_pub_key = (
            generate_keypair_and_public_key(eid, "device_id")
        )

        device_id_shared_key = entity_device_id_keypair.agree(
            base64.b64decode(request.client_device_id_pub_key)
        )

        long_lived_token = generate_llt(eid, device_id_shared_key)

        fields = {
            "eid": eid,
            "password_hash": password_hash,
            "country_code": country_code_ciphertext_b64,
            "device_id": compute_device_id(
                device_id_shared_key,
                identifier_value,
                base64.b64decode(request.client_device_id_pub_key),
            ),
            "client_publish_pub_key": request.client_publish_pub_key,
            "client_device_id_pub_key": request.client_device_id_pub_key,
            "publish_keypair": serialize_and_encrypt(entity_publish_keypair),
            "device_id_keypair": serialize_and_encrypt(entity_device_id_keypair),
        }
        if identifier_type == ContactType.EMAIL:
            fields["email_hash"] = identifier_hash
        if identifier_type == ContactType.PHONE:
            fields["phone_number_hash"] = identifier_hash

        create_entity(**fields)

        logger.info("Entity created successfully")

        return response(
            long_lived_token=long_lived_token,
            message="Entity created successfully",
            server_publish_pub_key=base64.b64encode(entity_publish_pub_key).decode(
                "utf-8"
            ),
            server_device_id_pub_key=base64.b64encode(entity_device_id_pub_key).decode(
                "utf-8"
            ),
        )

    def initiate_creation():
        if is_captcha_enabled():
            logger.debug("Captcha verification is enabled.")

            captcha_success, captcha_error = self.handle_captcha_verification(
                context, request, response
            )
            if not captcha_success:
                return captcha_error

        identifier_type, identifier_value = self.get_identifier(request)
        entity_lock = self._get_entity_lock(identifier_value)
        with entity_lock:
            success, pow_response = self.handle_pow_initialization(
                context, request, response, OTPAction.SIGNUP
            )

            if not success:
                return pow_response

            message, expires = pow_response

            signups.create_record(
                country_code=request.country_code,
                source="platforms",
                auth_method="email"
                if identifier_type == ContactType.EMAIL
                else "phone_number",
            )

            return response(
                requires_ownership_proof=True,
                message=message,
                next_attempt_timestamp=expires,
            )

    def validate_fields():
        invalid_fields = self.handle_request_field_validation(
            context,
            request,
            response,
            [
                ("phone_number", "email_address"),
                "country_code",
                "password",
                "client_publish_pub_key",
                "client_device_id_pub_key",
            ],
        )
        if invalid_fields:
            return invalid_fields

        password_error = validate_password_strength(request.password)
        if password_error:
            return self.handle_create_grpc_error_response(
                context,
                response,
                password_error,
                grpc.StatusCode.INVALID_ARGUMENT,
            )

        return None

    try:
        invalid_fields_response = validate_fields()
        if invalid_fields_response:
            return invalid_fields_response

        identifier_type, identifier_value = self.get_identifier(request)
        if identifier_type == ContactType.EMAIL:
            email_address = identifier_value
            email_address_hash = hash_data(email_address)
            entity_obj = find_entity(email_hash=email_address_hash)
        else:
            phone_number = identifier_value
            phone_number_hash = hash_data(phone_number)
            entity_obj = find_entity(phone_number_hash=phone_number_hash)

        if entity_obj:
            return self.handle_create_grpc_error_response(
                context,
                response,
                f"Entity with this {identifier_type.value} already exists.",
                grpc.StatusCode.ALREADY_EXISTS,
            )

        if request.ownership_proof_response:
            return complete_creation()

        return initiate_creation()

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
