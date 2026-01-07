# SPDX-License-Identifier: GPL-3.0-only
"""gRPC Entity Service V1"""

import base64
import re
import threading
import traceback
import weakref

import grpc
import phonenumbers

from base_logger import get_logger
from protos.v1 import vault_pb2_grpc
from src.entity import find_entity
from src.grpc_entity_services.v1.authenticate import AuthenticateEntity
from src.grpc_entity_services.v1.create import CreateEntity
from src.grpc_entity_services.v1.delete import DeleteEntity
from src.grpc_entity_services.v1.list_tokens import ListEntityStoredTokens
from src.grpc_entity_services.v1.reset_password import ResetPassword
from src.grpc_entity_services.v1.update_password import UpdateEntityPassword
from src.long_lived_token import verify_llt
from src.otp_service import send_otp, verify_otp
from src.recaptcha import verify_captcha
from src.types import ContactType
from src.utils import decrypt_and_deserialize, hash_data, is_valid_x25519_public_key

logger = get_logger(__name__)


class EntityServiceV1(vault_pb2_grpc.EntityServicer):
    """Entity Service Descriptor V1"""

    _entity_locks: "weakref.WeakValueDictionary[str, threading.Lock]" = (
        weakref.WeakValueDictionary()
    )
    _locks_lock: threading.Lock = threading.Lock()

    @classmethod
    def _get_entity_lock(cls, identifier: str) -> threading.Lock:
        """Get or create a lock for a specific entity using hashed identifier."""
        identifier_hash = hash_data(identifier)
        with cls._locks_lock:
            lock = cls._entity_locks.get(identifier_hash)
            if lock is None:
                lock = threading.Lock()
                cls._entity_locks[identifier_hash] = lock
                logger.debug("Created new lock for hashed identifier")
            return lock

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

        def field_missing_error(field_names):
            return self.handle_create_grpc_error_response(
                context,
                response,
                f"Missing required field: {' or '.join(field_names)}",
                grpc.StatusCode.INVALID_ARGUMENT,
            )

        def validate_field(field):
            if isinstance(field, tuple):
                if not any(getattr(request, f, None) for f in field):
                    return field_missing_error(field)
            else:
                if not getattr(request, field, None):
                    return field_missing_error([field])
            return None

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

        def validate_email_address():
            email_address = getattr(request, "email_address", None)
            if email_address:
                email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
                if not re.match(email_pattern, email_address):
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        "Invalid email address format.",
                        grpc.StatusCode.INVALID_ARGUMENT,
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

        for field in required_fields:
            validation_error = validate_field(field)
            if validation_error:
                return validation_error

        phone_number_error = validate_phone_number()
        if phone_number_error:
            return phone_number_error

        email_address_error = validate_email_address()
        if email_address_error:
            return email_address_error

        x25519_keys_error = validate_x25519_keys()
        if x25519_keys_error:
            return x25519_keys_error

        return None

    def handle_pow_verification(self, context, request, response, action):
        """Handle proof of ownership verification."""
        identifier_type, identifier_value = self.get_identifier(request)
        success, message = verify_otp(
            identifier_value, request.ownership_proof_response, action, identifier_type
        )
        if not success:
            return success, self.handle_create_grpc_error_response(
                context,
                response,
                message,
                grpc.StatusCode.UNAUTHENTICATED,
            )
        return success, message

    def handle_pow_initialization(self, context, request, response, action):
        """Handle proof of ownership initialization."""
        identifier_type, identifier_value = self.get_identifier(request)
        success, message, expires = send_otp(identifier_value, action, identifier_type)
        if not success:
            return success, self.handle_create_grpc_error_response(
                context,
                response,
                message,
                grpc.StatusCode.INVALID_ARGUMENT,
            )
        return success, (message, expires)

    def handle_captcha_verification(self, context, request, response):
        """Handle captcha verification for entity operations."""
        if not getattr(request, "captcha_token", None):
            return False, self.handle_create_grpc_error_response(
                context,
                response,
                "Missing required field: captcha_token",
                grpc.StatusCode.INVALID_ARGUMENT,
            )

        success, message = verify_captcha(request.captcha_token)
        if not success:
            return False, self.handle_create_grpc_error_response(
                context,
                response,
                message,
                grpc.StatusCode.PERMISSION_DENIED,
            )

        return True, None

    def handle_long_lived_token_validation(self, request, context, response):
        """Handles the validation of a long-lived token from the request."""

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

        def extract_token(long_lived_token):
            try:
                eid, llt = long_lived_token.split(":", 1)
                return eid, llt
            except ValueError as err:
                return None, create_error_response(f"Token extraction error: {err}")

        def validate_entity(eid):
            entity_obj = find_entity(eid=eid)
            if not entity_obj:
                return None, create_error_response(
                    f"Possible token tampering detected. Entity not found with eid: {eid}"
                )
            if not entity_obj.device_id:
                return None, create_error_response(
                    f"No device ID found for entity with EID: {eid}"
                )
            return entity_obj, None

        def validate_long_lived_token(llt, entity_obj):
            if not entity_obj.client_device_id_pub_key:
                return None, create_error_response(
                    "Entity's client device ID public key is missing. Should re-authenticate."
                )

            if not entity_obj.device_id_keypair:
                return None, create_error_response(
                    "Entity's device ID keypair is missing. Should re-authenticate."
                )

            entity_device_id_keypair = decrypt_and_deserialize(
                entity_obj.device_id_keypair
            )

            if not entity_device_id_keypair:
                return None, create_error_response(
                    "Failed to load entity's device ID keypair. Should re-authenticate."
                )

            try:
                entity_device_id_shared_key = entity_device_id_keypair.agree(
                    base64.b64decode(entity_obj.client_device_id_pub_key),
                )
            except Exception as e:
                return None, create_error_response(
                    f"Failed to compute shared key: {str(e)}. Should re-authenticate."
                )

            llt_payload, llt_error = verify_llt(llt, entity_device_id_shared_key)

            if not llt_payload:
                return None, create_error_response(llt_error)

            if llt_payload.get("eid") != entity_obj.eid.hex:
                return None, create_error_response(
                    f"Possible token tampering detected. EID mismatch: {entity_obj.eid}"
                )

            return llt_payload, None

        eid, llt = extract_token(request.long_lived_token)
        if llt is None:
            return None, llt

        entity_obj, entity_error = validate_entity(eid)
        if entity_error:
            return None, entity_error

        _, token_error = validate_long_lived_token(llt, entity_obj)
        if token_error:
            return None, token_error

        return entity_obj, None

    def clean_phone_number(self, phone_number):
        """Cleans up the phone number by removing spaces."""
        return re.sub(r"\s+", "", phone_number)

    def get_identifier(self, request):
        """Gets the request identifier."""
        phone_number = getattr(request, "phone_number", None)
        email_address = getattr(request, "email_address", None)
        if email_address:
            return ContactType.EMAIL, email_address
        return ContactType.PHONE, phone_number

    AuthenticateEntity = AuthenticateEntity
    CreateEntity = CreateEntity
    DeleteEntity = DeleteEntity
    ListEntityStoredTokens = ListEntityStoredTokens
    ResetPassword = ResetPassword
    UpdateEntityPassword = UpdateEntityPassword
