# SPDX-License-Identifier: GPL-3.0-only
"""Reset Password gRPC service implementation"""

import secrets
from datetime import datetime, timedelta, timezone

import grpc

from base_logger import get_logger
from protos.v2 import vault_pb2
from src import stats
from src.device_id import derive_device_id_v1
from src.entity import find_entity
from src.long_lived_token import derive_llt_v1
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
    create_x25519_keypair,
    decode_and_decrypt,
    encrypt_data,
    hash_data,
    hash_password,
    load_ed25519_private_key,
    serialize_and_encrypt,
)

logger = get_logger(__name__)


def ResetPassword(self, request, context):
    """Handles resetting an entity's password."""

    response = vault_pb2.ResetPasswordResponse

    if hasattr(request, "phone_number"):
        request.phone_number = self.clean_phone_number(request.phone_number)

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
        invalid_fields = self.handle_request_field_validation(
            context,
            request,
            response,
            [
                "new_password",
                "client_id_pub_key",
                "client_ratchet_pub_key",
                "client_header_pub_key",
                "client_next_header_pub_key",
                "client_nonce",
            ],
        )
        if invalid_fields:
            return invalid_fields

        password_error = validate_password_strength(request.new_password)
        if password_error:
            return self.handle_create_grpc_error_response(
                context,
                response,
                password_error,
                grpc.StatusCode.INVALID_ARGUMENT,
            )

        success, pow_response = self.handle_pow_verification(
            context, request, response, OTPAction.RESET_PASSWORD
        )
        if not success:
            return pow_response

        eid = entity_obj.eid.hex
        password_hash = hash_password(request.new_password)

        clear_keystore(eid)
        identity_key_success, server_identity_response = self.get_server_identity_key(
            context, response
        )
        if not identity_key_success:
            return server_identity_response

        server_ratchet_keypair, server_ratchet_pub_keys = create_x25519_keypair(
            eid, "ratchet", encrypt_headers=True
        )
        server_nonce = secrets.token_bytes(16)

        si_private_key = load_ed25519_private_key()

        payload = {
            "eid": eid,
            "iss": "https://smswithoutborders.com",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(days=3650),
        }

        long_lived_token = derive_llt_v1(payload, si_private_key)

        entity_obj.password_hash = password_hash
        entity_obj.server_state = None
        entity_obj.device_id = derive_device_id_v1(
            client_id_pub_key=request.client_id_pub_key
        ).hex()
        entity_obj.client_id_pub_key = request.client_id_pub_key
        entity_obj.client_ratchet_pub_key = request.client_ratchet_pub_key
        entity_obj.client_header_pub_key = request.client_header_pub_key
        entity_obj.client_next_header_pub_key = request.client_next_header_pub_key
        entity_obj.client_nonce = encrypt_data(request.client_nonce)
        entity_obj.server_ratchet_keypair = serialize_and_encrypt(
            server_ratchet_keypair
        )
        entity_obj.server_nonce = encrypt_data(server_nonce)
        entity_obj.save(
            only=[
                "password_hash",
                "server_state",
                "device_id",
                "client_id_pub_key",
                "client_ratchet_pub_key",
                "client_header_pub_key",
                "client_next_header_pub_key",
                "client_nonce",
                "server_ratchet_keypair",
                "server_nonce",
            ]
        )

        country_code = decode_and_decrypt(entity_obj.country_code)
        identifier_type, _ = self.get_identifier(request)
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
            server_ratchet_pub_key=server_ratchet_pub_keys["public_key"],
            server_header_pub_key=server_ratchet_pub_keys["header_public_key"],
            server_next_header_pub_key=server_ratchet_pub_keys[
                "next_header_public_key"
            ],
            server_nonce=server_nonce,
        )

    try:
        invalid_fields = self.handle_request_field_validation(
            context,
            request,
            response,
            [("phone_number", "email_address")],
        )
        if invalid_fields:
            return invalid_fields

        identifier_type, identifier_value = self.get_identifier(request)
        if identifier_type == ContactType.EMAIL:
            email_address = identifier_value
            email_address_hash = hash_data(email_address)
            entity_obj = find_entity(email_hash=email_address_hash)
        else:
            phone_number = identifier_value
            phone_number_hash = hash_data(phone_number)
            entity_obj = find_entity(phone_number_hash=phone_number_hash)

        if not entity_obj or not entity_obj.is_verified:
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
