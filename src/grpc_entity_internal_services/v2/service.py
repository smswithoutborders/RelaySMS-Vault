# SPDX-License-Identifier: GPL-3.0-only
"""gRPC Entity Internal Service V2"""

import base64
import re
import threading
import time
import traceback
import weakref

import grpc
import phonenumbers
from cachetools import TTLCache
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from base_logger import get_logger
from protos.v2 import vault_pb2_grpc
from src.db_models import StaticKeypairs
from src.entity import find_entity
from src.grpc_entity_internal_services.v2.decrypt_payloads import DecryptPayload
from src.grpc_entity_internal_services.v2.store_token import StoreEntityToken
from src.long_lived_token import verify_llt_v1
from src.utils import (
    decrypt_and_deserialize,
    get_configs,
    is_valid_x25519_public_key,
    load_and_decode_key,
)

logger = get_logger(__name__)

STATIC_KEYPAIR_VERSION = "v1"
STATIC_KEYPAIR_IDENTIFIER = 254
NONCE_CACHE_TTL = int(get_configs("NONCE_CACHE_TTL", default_value="600"))


class EntityInternalServiceV2(vault_pb2_grpc.EntityInternalServicer):
    """Entity Internal Service Descriptor V2"""

    _entity_locks: "weakref.WeakValueDictionary[str, threading.Lock]" = (
        weakref.WeakValueDictionary()
    )
    _locks_lock: threading.Lock = threading.Lock()
    _nonce_cache: TTLCache = TTLCache(maxsize=10000, ttl=NONCE_CACHE_TTL)
    _nonce_lock: threading.Lock = threading.Lock()

    @classmethod
    def _get_entity_lock(cls, entity_id: str) -> threading.Lock:
        """Get or create a lock for a specific entity."""
        with cls._locks_lock:
            lock = cls._entity_locks.get(entity_id)
            if lock is None:
                lock = threading.Lock()
                cls._entity_locks[entity_id] = lock
                logger.debug("Created new lock for entity")
            return lock

    @classmethod
    def _get_nonce_lock(cls) -> threading.Lock:
        """Get the nonce lock for thread-safe nonce cache access."""
        return cls._nonce_lock

    def handle_create_grpc_error_response(
        self, context, response, error, status_code, **kwargs
    ):
        """Handles the creation of a gRPC error response."""
        user_msg = kwargs.get("user_msg")
        error_type = kwargs.get("error_type")
        error_prefix = kwargs.get("error_prefix")

        if not user_msg:
            user_msg = str(error)

        if error_type == "UNKNOWN":
            traceback.print_exception(type(error), error, error.__traceback__)

        error_message = f"{error_prefix}: {user_msg}" if error_prefix else user_msg

        logger.error(error_message)

        context.set_details(error_message)
        context.set_code(status_code)

        return response()

    def handle_request_field_validation(
        self, context, request, response, required_fields
    ):
        """Validates the fields in the gRPC request."""
        x25519_fields = {"client_publish_pub_key", "client_device_id_pub_key"}

        for field in required_fields:
            if isinstance(field, tuple):
                if not any(getattr(request, f, None) for f in field):
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        f"Missing required field: {' or '.join(field)}",
                        grpc.StatusCode.INVALID_ARGUMENT,
                    )
            else:
                if not getattr(request, field, None):
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        f"Missing required field: {field}",
                        grpc.StatusCode.INVALID_ARGUMENT,
                    )

        def validate_phone_number():
            phone_number = getattr(request, "phone_number", None)
            country_code = getattr(request, "country_code", None)
            if phone_number and country_code:
                try:
                    parsed_number = phonenumbers.parse(phone_number)
                    expected_country = phonenumbers.region_code_for_country_code(
                        parsed_number.country_code
                    )
                    given_country = country_code.upper()
                    if expected_country != given_country:
                        if not (given_country == "CA" and expected_country == "US"):
                            return self.handle_create_grpc_error_response(
                                context,
                                response,
                                f"The phone number does not match the provided country code "
                                f"{given_country}. Expected country code is {expected_country}.",
                                grpc.StatusCode.INVALID_ARGUMENT,
                            )
                except phonenumbers.phonenumberutil.NumberParseException as e:
                    match = re.split(r"\(\d\)\s*(.*)", str(e))
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        e,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        user_msg=f"The phone number is invalid. {match[1].strip()}",
                        error_type="UNKNOWN",
                    )
            return None

        def validate_x25519_keys():
            for field in x25519_fields & set(required_fields):
                is_valid, error = is_valid_x25519_public_key(getattr(request, field))
                if not is_valid:
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        f"The {field} field has an {error}.",
                        grpc.StatusCode.INVALID_ARGUMENT,
                    )
            return None

        phone_number_error = validate_phone_number()
        if phone_number_error:
            return phone_number_error

        x25519_keys_error = validate_x25519_keys()
        if x25519_keys_error:
            return x25519_keys_error

        return None

    def handle_long_lived_token_v1_validation(self, context, response):
        """Handles the validation of a long-lived token v1."""

        def create_error_response(error_msg):
            return self.handle_create_grpc_error_response(
                context,
                response,
                error_msg,
                grpc.StatusCode.UNAUTHENTICATED,
                user_msg=(
                    "The long-lived token is invalid. Please log in again to generate a new token."
                ),
            )

        def extract_metadata(context) -> tuple[dict | None, grpc.RpcError | None]:
            metadata = dict(context.invocation_metadata())

            authorization = metadata.get("authorization")
            if not authorization:
                return None, create_error_response("Missing Authorization header")

            if not authorization.startswith("Bearer "):
                return None, create_error_response(
                    "Invalid Authorization header format. Expected 'Bearer <token>'"
                )

            result = {
                "llt": authorization[7:],
                "signature": metadata.get("x-sig"),
                "nonce": metadata.get("x-nonce"),
                "timestamp": metadata.get("x-timestamp"),
                "method_name": metadata.get("x-method-name") or context.method_name,
            }

            missing = [k for k in ("signature", "nonce", "timestamp") if not result[k]]
            if missing:
                return None, create_error_response(
                    f"Missing required metadata: {', '.join(m.upper().replace('_', '-') for m in missing)}"
                )

            return result, None

        try:
            metadata, metadata_error = extract_metadata(context)
            if metadata_error:
                return None, metadata_error

            llt = metadata["llt"]
            timestamp = metadata["timestamp"]
            nonce = metadata["nonce"]
            signature = metadata["signature"]
            method_name = metadata["method_name"]

            signature_key = load_and_decode_key(
                get_configs("SIGNATURE_KEY_FILE", strict=True), 32
            )

            payload, llt_error = verify_llt_v1(llt=llt, signing_key=signature_key)

            if llt_error:
                return None, create_error_response(llt_error)

            eid = payload.get("eid")
            if not eid:
                return None, create_error_response("EID not found in token payload")

            entity_obj = find_entity(eid=eid)
            if not entity_obj:
                return None, create_error_response(
                    f"Possible token tampering detected. Entity not found with eid: {eid}"
                )

            if not entity_obj.device_id:
                return None, create_error_response(
                    f"No device ID found for entity with EID: {eid}"
                )

            if not entity_obj.client_id_pub_key:
                return None, create_error_response(
                    "Client identity public key not found. Should re-authenticate."
                )

            current_timestamp = int(time.time())
            timestamp_diff = abs(current_timestamp - int(timestamp))

            if timestamp_diff > NONCE_CACHE_TTL:
                return None, create_error_response(
                    "Outdated timestamp detected in request."
                )

            with self._get_nonce_lock():
                if nonce in self._nonce_cache:
                    return None, create_error_response("Nonce has already been used.")
                self._nonce_cache[nonce] = True

            nonce_bytes = base64.urlsafe_b64decode(nonce)
            signature_bytes = base64.urlsafe_b64decode(signature)
            request_string_bytes = (
                method_name.encode() + timestamp.encode() + nonce_bytes
            )
            client_id_pub_key = Ed25519PublicKey.from_public_bytes(
                entity_obj.client_id_pub_key
            )
            client_id_pub_key.verify(signature_bytes, request_string_bytes)

            return entity_obj, None

        except InvalidSignature:
            err_msg = "Invalid signature for Client ID public key."
            return None, create_error_response(err_msg)
        except Exception as e:
            logger.error("Error validating LLT v1: %s", e)
            return None, create_error_response(str(e))

    def get_server_identity_key(self, context, response):
        """Handles getting server identity key."""
        server_static_keypair_record = StaticKeypairs.get_keypair(
            STATIC_KEYPAIR_IDENTIFIER, STATIC_KEYPAIR_VERSION
        )
        if (
            not server_static_keypair_record
            or server_static_keypair_record.status != "active"
        ):
            status = "not found" if not server_static_keypair_record else "not active"
            error_msg = (
                "The server public key identifier "
                f"'{STATIC_KEYPAIR_IDENTIFIER}' for version "
                f"{STATIC_KEYPAIR_VERSION} is {status}."
            )
            logger.error(error_msg)
            error_response = self.handle_create_grpc_error_response(
                context,
                response,
                error_msg,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
            )

            return False, error_response

        server_identity_keypair = decrypt_and_deserialize(
            server_static_keypair_record.keypair_bytes
        )
        return True, server_identity_keypair

    DecryptPayload = DecryptPayload
    StoreEntityToken = StoreEntityToken
