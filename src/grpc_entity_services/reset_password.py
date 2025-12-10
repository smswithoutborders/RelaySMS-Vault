# SPDX-License-Identifier: GPL-3.0-only
"""Reset Password gRPC service implementation"""

import base64

import grpc

import vault_pb2
from base_logger import get_logger
from src import stats
from src.device_id import compute_device_id
from src.entity import find_entity
from src.long_lived_token import generate_llt
from src.password_validation import validate_password_strength
from src.recaptcha import is_captcha_enabled
from src.types import (
    ContactType,
    EntityOrigin,
    OTPAction,
    StatsEventStage,
    StatsEventType,
)
from src.utils import (
    clear_keystore,
    decode_and_decrypt,
    generate_keypair_and_public_key,
    hash_data,
    hash_password,
    serialize_and_encrypt,
)

logger = get_logger(__name__)


def ResetPassword(self, request, context):
    """Handles resetting an entity's password."""

    response = vault_pb2.ResetPasswordResponse

    def initiate_reset(entity_obj):
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
                context, request, response, OTPAction.RESET_PASSWORD
            )
            if not success:
                return pow_response

            message, expires = pow_response

            country_code = decode_and_decrypt(entity_obj.country_code)

            stats.create(
                event_type=StatsEventType.RESET_PASSWORD,
                country_code=country_code,
                identifier_type=identifier_type,
                origin=EntityOrigin(entity_obj.origin),
                event_stage=StatsEventStage.INITIATE,
            )

            return response(
                requires_ownership_proof=True,
                message=message,
                next_attempt_timestamp=expires,
            )

    def complete_reset(entity_obj):
        success, pow_response = self.handle_pow_verification(
            context, request, response, OTPAction.RESET_PASSWORD
        )
        if not success:
            return pow_response

        eid = entity_obj.eid.hex
        password_hash = hash_password(request.new_password)

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

        entity_obj.password_hash = password_hash
        entity_obj.server_state = None
        identifier_type, identifier_value = self.get_identifier(request)
        entity_obj.device_id = compute_device_id(
            device_id_shared_key,
            identifier_value,
            base64.b64decode(request.client_device_id_pub_key),
        )
        entity_obj.client_publish_pub_key = request.client_publish_pub_key
        entity_obj.client_device_id_pub_key = request.client_device_id_pub_key
        entity_obj.publish_keypair = serialize_and_encrypt(entity_publish_keypair)
        entity_obj.device_id_keypair = serialize_and_encrypt(entity_device_id_keypair)
        entity_obj.save(
            only=[
                "password_hash",
                "server_state",
                "device_id",
                "client_publish_pub_key",
                "client_device_id_pub_key",
                "publish_keypair",
                "device_id_keypair",
            ]
        )

        country_code = decode_and_decrypt(entity_obj.country_code)

        stats.create(
            event_type=StatsEventType.RESET_PASSWORD,
            country_code=country_code,
            identifier_type=identifier_type,
            origin=EntityOrigin(entity_obj.origin),
            event_stage=StatsEventStage.COMPLETE,
        )

        return response(
            long_lived_token=long_lived_token,
            message="Password reset successfully!",
            server_publish_pub_key=base64.b64encode(entity_publish_pub_key).decode(
                "utf-8"
            ),
            server_device_id_pub_key=base64.b64encode(entity_device_id_pub_key).decode(
                "utf-8"
            ),
        )

    def validate_fields():
        invalid_fields = self.handle_request_field_validation(
            context,
            request,
            response,
            [
                ("phone_number", "email_address"),
                "new_password",
                "client_publish_pub_key",
                "client_device_id_pub_key",
            ],
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

        identifier_type, identifier_value = self.get_identifier(request)
        if identifier_type == ContactType.EMAIL:
            email_address = identifier_value
            email_address_hash = hash_data(email_address)
            entity_obj = find_entity(email_hash=email_address_hash)
        else:
            phone_number = identifier_value
            phone_number_hash = hash_data(phone_number)
            entity_obj = find_entity(phone_number_hash=phone_number_hash)

        if not entity_obj:
            return self.handle_create_grpc_error_response(
                context,
                response,
                f"Entity with this {identifier_type.value} not found.",
                grpc.StatusCode.NOT_FOUND,
            )

        if request.ownership_proof_response:
            return complete_reset(entity_obj)

        return initiate_reset(entity_obj)

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
