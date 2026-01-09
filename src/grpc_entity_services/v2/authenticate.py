# SPDX-License-Identifier: GPL-3.0-only
"""Authenticate Entity gRPC service implementation."""

import secrets

import grpc

from base_logger import get_logger
from protos.v2 import vault_pb2
from src import stats
from src.device_id import derive_device_id_v1
from src.entity import find_entity
from src.password_rate_limit import (
    clear_rate_limit,
    is_rate_limited,
    register_password_attempt,
)
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
    encrypt_data,
    generate_keypair_and_public_key,
    hash_data,
    hash_password,
    serialize_and_encrypt,
    verify_password,
)

logger = get_logger(__name__)


def AuthenticateEntity(self, request, context):
    """Handles the authentication of an entity."""

    response = vault_pb2.AuthenticateEntityResponse

    if hasattr(request, "phone_number"):
        request.phone_number = self.clean_phone_number(request.phone_number)

    def initiate_authentication(entity_obj):
        invalid_fields = self.handle_request_field_validation(
            context,
            request,
            response,
            [
                "password",
                "client_id_pub_key",
                "client_ratchet_pub_key",
                "client_nonce",
            ],
        )
        if invalid_fields:
            return invalid_fields

        if is_rate_limited(entity_obj.eid):
            return self.handle_create_grpc_error_response(
                context,
                response,
                "Too many password attempts. Please wait and try again later.",
                grpc.StatusCode.UNAVAILABLE,
            )

        if not entity_obj.password_hash:
            return response(
                requires_password_reset=True,
                message="Please reset your password to continue.",
            )

        register_password_attempt(entity_obj.eid)
        is_password_valid, upgrade_needed = verify_password(
            request.password, entity_obj.password_hash
        )
        if not is_password_valid:
            return self.handle_create_grpc_error_response(
                context,
                response,
                "Incorrect Password provided.",
                grpc.StatusCode.UNAUTHENTICATED,
                user_msg=(
                    "Incorrect credentials. Please double-check "
                    "your details and try again."
                ),
            )

        clear_rate_limit(entity_obj.eid)

        if upgrade_needed:
            try:
                logger.info("Upgrading password hash for entity")
                entity_obj.password_hash = hash_password(request.password)
                entity_obj.save(only=["password_hash"])
            except Exception as e:
                logger.error("Failed to upgrade password hash: %s", str(e))

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
                context, request, response, OTPAction.AUTH
            )
            if not success:
                return pow_response

            message, expires = pow_response
            entity_obj.device_id = None
            entity_obj.server_state = None
            entity_obj.client_id_pub_key = request.client_id_pub_key
            entity_obj.client_ratchet_pub_key = request.client_ratchet_pub_key
            entity_obj.client_nonce = encrypt_data(request.client_nonce)
            entity_obj.save(
                only=[
                    "device_id",
                    "server_state",
                    "client_id_pub_key",
                    "client_ratchet_pub_key",
                    "client_nonce",
                ]
            )

            country_code = decode_and_decrypt(entity_obj.country_code)
            origin = entity_obj.origin

            stats.create(
                event_type=StatsEventType.AUTH,
                country_code=country_code,
                identifier_type=identifier_type,
                origin=EntityOrigin(origin),
                event_stage=StatsEventStage.INITIATE,
            )

            return response(
                requires_ownership_proof=True,
                message=message,
                next_attempt_timestamp=expires,
            )

    def complete_authentication(entity_obj):
        success, pow_response = self.handle_pow_verification(
            context, request, response, OTPAction.AUTH
        )
        if not success:
            return pow_response

        eid = entity_obj.eid.hex

        clear_keystore(eid, "ratchet")
        identity_key_success, server_identity_response = self.get_server_identity_key(
            context, response
        )
        if not identity_key_success:
            return server_identity_response

        server_ratchet_keypair, server_ratchet_pub_key = (
            generate_keypair_and_public_key(eid, "ratchet")
        )
        server_nonce = secrets.token_bytes(16)

        # long_lived_token = generate_llt(eid, device_id_shared_key)

        entity_obj.server_ratchet_keypair = serialize_and_encrypt(
            server_ratchet_keypair
        )
        entity_obj.server_nonce = encrypt_data(server_nonce)
        entity_obj.device_id = derive_device_id_v1(
            client_id_pub_key=entity_obj.client_id_pub_key
        ).hex()
        entity_obj.save(only=["server_ratchet_keypair", "server_nonce", "device_id"])

        country_code = decode_and_decrypt(entity_obj.country_code)
        origin = entity_obj.origin

        stats.create(
            event_type=StatsEventType.AUTH,
            country_code=country_code,
            identifier_type=identifier_type,
            origin=EntityOrigin(origin),
            event_stage=StatsEventStage.COMPLETE,
        )

        return response(
            long_lived_token="",
            message="Entity authenticated successfully",
            server_ratchet_pub_key=server_ratchet_pub_key,
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
            return complete_authentication(entity_obj)

        return initiate_authentication(entity_obj)

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
