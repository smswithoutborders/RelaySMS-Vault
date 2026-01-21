# SPDX-License-Identifier: GPL-3.0-only
"""Authenticate Entity gRPC service implementation."""

import secrets
from datetime import datetime, timedelta, timezone

import grpc

from base_logger import get_logger
from protos.v2 import vault_pb2
from src.db_models import Entity, EntityDraft, Stats, database
from src.device_id import derive_device_id_v1
from src.long_lived_token import derive_llt_v1
from src.password_rate_limit import (
    clear_rate_limit,
    is_rate_limited,
    register_password_attempt,
)
from src.recaptcha import is_captcha_enabled
from src.types import ContactType, OTPAction, StatsEventStage, StatsEventType
from src.utils import (
    clear_keystore,
    create_x25519_keypair,
    decode_and_decrypt,
    encrypt_data,
    get_configs,
    hash_data,
    hash_password,
    load_and_decode_key,
    serialize_and_encrypt,
    verify_password,
)

logger = get_logger(__name__)


def AuthenticateEntity(self, request, context):
    """Handles the authentication of an entity."""

    response = vault_pb2.AuthenticateEntityResponse

    if hasattr(request, "phone_number"):
        request.phone_number = self.clean_phone_number(request.phone_number)

    def initiate_authentication():
        invalid_fields = self.handle_request_field_validation(
            context,
            request,
            response,
            [
                "password",
                "client_id_pub_key",
                "client_ratchet_pub_key",
                "client_header_pub_key",
                "client_next_header_pub_key",
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

        success, pow_response = self.handle_pow_initialization(
            context, request, response, OTPAction.AUTH
        )
        if not success:
            return pow_response

        message, expires = pow_response

        fields = {
            "eid": entity_obj.eid,
            "client_id_pub_key": request.client_id_pub_key,
            "client_ratchet_pub_key": request.client_ratchet_pub_key,
            "client_header_pub_key": request.client_header_pub_key,
            "client_next_header_pub_key": request.client_next_header_pub_key,
            "client_nonce": encrypt_data(request.client_nonce),
            "purpose": StatsEventType.AUTH.value,
        }

        if identifier_type == ContactType.EMAIL:
            fields["email_hash"] = hash_value
        elif identifier_type == ContactType.PHONE:
            fields["phone_number_hash"] = hash_value

        country_code = decode_and_decrypt(entity_obj.country_code)
        origin = entity_obj.origin

        with database.atomic():
            EntityDraft.replace(**fields).execute()
            Stats.create(
                event_type=StatsEventType.AUTH.value,
                country_code=country_code,
                identifier_type=identifier_type.value,
                origin=origin,
                event_stage=StatsEventStage.INITIATE.value,
            )

        return response(
            requires_ownership_proof=True,
            message=message,
            next_attempt_timestamp=expires,
        )

    def complete_authentication():
        success, pow_response = self.handle_pow_verification(
            context, request, response, OTPAction.AUTH
        )
        if not success:
            return pow_response

        entity_draft_obj = (
            EntityDraft.get_or_none(email_hash=hash_value)
            if identifier_type == ContactType.EMAIL
            else EntityDraft.get_or_none(phone_number_hash=hash_value)
        )

        if not entity_draft_obj:
            return self.handle_create_grpc_error_response(
                context,
                response,
                "Invalid request. Please initiate authentication first.",
                grpc.StatusCode.FAILED_PRECONDITION,
            )

        if not entity_draft_obj.purpose == StatsEventType.AUTH.value:
            return self.handle_create_grpc_error_response(
                context,
                response,
                "Invalid request. Entity draft purpose mismatch.",
                grpc.StatusCode.FAILED_PRECONDITION,
            )

        eid = entity_obj.eid.hex

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

        signature_key = load_and_decode_key(
            get_configs("SIGNATURE_KEY_FILE", strict=True), 32
        )

        payload = {
            "eid": eid,
            "iss": "https://smswithoutborders.com",
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(days=3650),
        }

        long_lived_token = derive_llt_v1(payload=payload, signing_key=signature_key)

        entity_obj.device_id = derive_device_id_v1(
            client_id_pub_key=entity_draft_obj.client_id_pub_key
        ).hex()
        entity_obj.server_state = None
        entity_obj.client_id_pub_key = entity_draft_obj.client_id_pub_key
        entity_obj.client_ratchet_pub_key = entity_draft_obj.client_ratchet_pub_key
        entity_obj.client_header_pub_key = entity_draft_obj.client_header_pub_key
        entity_obj.client_next_header_pub_key = (
            entity_draft_obj.client_next_header_pub_key
        )
        entity_obj.client_nonce = entity_draft_obj.client_nonce
        entity_obj.server_ratchet_keypair = serialize_and_encrypt(
            server_ratchet_keypair
        )
        entity_obj.server_nonce = encrypt_data(server_nonce)

        country_code = decode_and_decrypt(entity_obj.country_code)
        origin = entity_obj.origin

        with database.atomic():
            entity_obj.save(
                only=[
                    "device_id",
                    "server_state",
                    "client_id_pub_key",
                    "client_ratchet_pub_key",
                    "client_header_pub_key",
                    "client_next_header_pub_key",
                    "client_nonce",
                    "server_ratchet_keypair",
                    "server_nonce",
                ]
            )
            entity_draft_obj.delete_instance()
            Stats.create(
                event_type=StatsEventType.AUTH.value,
                country_code=country_code,
                identifier_type=identifier_type.value,
                origin=origin,
                event_stage=StatsEventStage.COMPLETE.value,
            )

        return response(
            long_lived_token=long_lived_token,
            message="Entity authenticated successfully",
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
        hash_value = hash_data(identifier_value)

        entity_lock = self._get_entity_lock(hash_value)
        with entity_lock:
            entity_obj = (
                Entity.get_or_none(email_hash=hash_value)
                if identifier_type == ContactType.EMAIL
                else Entity.get_or_none(phone_number_hash=hash_value)
            )

            if not entity_obj:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    f"Entity with this {identifier_type.value} not found.",
                    grpc.StatusCode.NOT_FOUND,
                )

            if request.ownership_proof_response:
                return complete_authentication()

            return initiate_authentication()

    except Exception as e:
        return self.handle_create_grpc_error_response(
            context,
            response,
            e,
            grpc.StatusCode.INTERNAL,
            user_msg="Oops! Something went wrong. Please try again later.",
            error_type="UNKNOWN",
        )
