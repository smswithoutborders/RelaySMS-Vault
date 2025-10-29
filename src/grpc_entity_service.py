"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import base64
import re
import traceback
import json
import threading
import weakref

import grpc
import phonenumbers

import vault_pb2
import vault_pb2_grpc

from src import signups
from src.entity import create_entity, find_entity
from src.tokens import fetch_entity_tokens, update_entity_tokens
from src.crypto import generate_hmac, verify_hmac
from src.otp_service import send_otp, verify_otp
from src.recaptcha import is_captcha_enabled, get_captcha, verify_captcha
from src.utils import (
    load_key,
    get_configs,
    encrypt_and_encode,
    generate_keypair_and_public_key,
    generate_eid,
    is_valid_x25519_public_key,
    decrypt_and_decode,
    load_keypair_object,
    clear_keystore,
    get_platforms_by_protocol_type,
)
from src.long_lived_token import generate_llt, verify_llt
from src.device_id import compute_device_id
from src.password_validation import validate_password_strength
from src.password_rate_limit import (
    is_rate_limited,
    clear_rate_limit,
    register_password_attempt,
)
from base_logger import get_logger

logger = get_logger(__name__)

HASHING_KEY = load_key(get_configs("HASHING_SALT", strict=True), 32)


class EntityService(vault_pb2_grpc.EntityServicer):
    """Entity Service Descriptor"""

    _entity_locks: "weakref.WeakValueDictionary[str, threading.Lock]" = (
        weakref.WeakValueDictionary()
    )
    _locks_lock: threading.Lock = threading.Lock()

    @classmethod
    def _get_entity_lock(cls, identifier: str) -> threading.Lock:
        """
        Get or create a lock for a specific entity.
        Locks are automatically removed when no longer used.
        """
        with cls._locks_lock:
            lock = cls._entity_locks.get(identifier)
            if lock is None:
                lock = threading.Lock()
                cls._entity_locks[identifier] = lock
                logger.debug("Created new lock for identifier %s", identifier)
            return lock

    def handle_create_grpc_error_response(
        self, context, response, error, status_code, **kwargs
    ):
        """
        Handles the creation of a gRPC error response.

        Args:
            context (grpc.ServicerContext): The gRPC context object.
            response (callable): The gRPC response object.
            error (Exception or str): The exception instance or error message.
            status_code (grpc.StatusCode): The gRPC status code to be set for the response
                (e.g., grpc.StatusCode.INTERNAL).
            user_msg (str, optional): A user-friendly error message to be returned to the client.
                If not provided, the `error` message will be used.
            error_type (str, optional): A string identifying the type of error.
                When set to "UNKNOWN", it triggers the logging of a full exception traceback
                for debugging purposes.
            error_prefix (str, optional): An optional prefix to prepend to the error message
                for additional context (e.g., indicating the specific operation or subsystem
                that caused the error).

        Returns:
            An instance of the specified response with the error set.
        """
        user_msg = kwargs.get("user_msg")
        error_type = kwargs.get("error_type")
        error_prefix = kwargs.get("error_prefix")

        if not user_msg:
            user_msg = str(error)

        if error_type == "UNKNOWN":
            traceback.print_exception(type(error), error, error.__traceback__)

        error_message = f"{error_prefix}: {user_msg}" if error_prefix else user_msg
        context.set_details(error_message)
        context.set_code(status_code)

        return response()

    def handle_request_field_validation(
        self, context, request, response, required_fields
    ):
        """
        Validates the fields in the gRPC request.

        Args:
            context: gRPC context.
            request: gRPC request object.
            response: gRPC response object.
            required_fields (list): List of required fields, can include tuples.

        Returns:
            None or response: None if no missing fields,
                error response otherwise.
        """
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

        x25519_keys_error = validate_x25519_keys()
        if x25519_keys_error:
            return x25519_keys_error

        return None

    def handle_pow_verification(self, context, request, response):
        """
        Handle proof of ownership verification.

        Args:
            context: gRPC context.
            request: gRPC request object.
            response: gRPC response object.

        Returns:
            tuple: Tuple containing success flag and message.
        """
        success, message = verify_otp(
            request.phone_number, request.ownership_proof_response
        )
        if not success:
            return success, self.handle_create_grpc_error_response(
                context,
                response,
                message,
                grpc.StatusCode.UNAUTHENTICATED,
            )
        return success, message

    def handle_pow_initialization(self, context, request, response):
        """
        Handle proof of ownership initialization.

        Args:
            context: gRPC context.
            request: gRPC request object.
            response: gRPC response object.

        Returns:
            tuple:
                - success flag (bool)
                - tuple or response:
                    - message.
                    - expiration time.
        """
        success, message, expires = send_otp(request.phone_number)
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
        success, message = verify_captcha(request.captcha_id, request.captcha_answer)
        if not success:
            return False, self.handle_create_grpc_error_response(
                context,
                response,
                message,
                grpc.StatusCode.PERMISSION_DENIED,
            )

        return True, None

    def handle_captcha_retrieval(self, context, response):
        """Handle captcha retrieval for entity operations."""
        captcha_data, captcha_message = get_captcha()
        if not captcha_data:
            return False, self.handle_create_grpc_error_response(
                context,
                response,
                captcha_message,
                grpc.StatusCode.UNAVAILABLE,
                user_msg="Unable to generate captcha. Please try again.",
            )

        captcha_id = captcha_data.get("id", "")
        captcha_image = captcha_data.get("image", "")

        return True, (captcha_id, captcha_image)

    def handle_long_lived_token_validation(self, request, context, response):
        """
        Handles the validation of a long-lived token from the request.

        Args:
            context: gRPC context.
            request: gRPC request object.
            response: gRPC response object.

        Returns:
            tuple: Tuple containing entity object, and error response.
        """

        def create_error_response(error_msg):
            return self.handle_create_grpc_error_response(
                context,
                response,
                error_msg,
                grpc.StatusCode.UNAUTHENTICATED,
                user_msg=(
                    "The long-lived token is invalid. Please log in again to generate a new token."
                ),
                error_type="UNKNOWN",
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

            entity_device_id_keypair = load_keypair_object(entity_obj.device_id_keypair)

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

    def CreateEntity(self, request, context):
        """Handles the creation of an entity."""

        response = vault_pb2.CreateEntityResponse

        if hasattr(request, "phone_number"):
            request.phone_number = self.clean_phone_number(request.phone_number)

        def complete_creation():
            success, pow_response = self.handle_pow_verification(
                context, request, response
            )
            if not success:
                return pow_response

            phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
            eid = generate_eid(phone_number_hash)
            password_hash = generate_hmac(HASHING_KEY, request.password)
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
                "phone_number_hash": phone_number_hash,
                "password_hash": password_hash,
                "country_code": country_code_ciphertext_b64,
                "device_id": compute_device_id(
                    device_id_shared_key,
                    request.phone_number,
                    base64.b64decode(request.client_device_id_pub_key),
                ),
                "client_publish_pub_key": request.client_publish_pub_key,
                "client_device_id_pub_key": request.client_device_id_pub_key,
                "publish_keypair": entity_publish_keypair.serialize(),
                "device_id_keypair": entity_device_id_keypair.serialize(),
            }

            create_entity(**fields)

            logger.info("Entity created successfully")

            return response(
                long_lived_token=long_lived_token,
                message="Entity created successfully",
                server_publish_pub_key=base64.b64encode(entity_publish_pub_key).decode(
                    "utf-8"
                ),
                server_device_id_pub_key=base64.b64encode(
                    entity_device_id_pub_key
                ).decode("utf-8"),
            )

        def initiate_creation():
            if is_captcha_enabled():
                logger.debug("Captcha verification is enabled.")
                captcha_id = getattr(request, "captcha_id", None)
                captcha_answer = getattr(request, "captcha_answer", None)

                if not captcha_id or not captcha_answer:
                    captcha_success, captcha_result = self.handle_captcha_retrieval(
                        context, response
                    )
                    if not captcha_success:
                        return captcha_result

                    captcha_id, captcha_image = captcha_result

                    return response(
                        requires_captcha=True,
                        message="Solve the captcha to proceed.",
                        captcha_id=captcha_id,
                        captcha_image=captcha_image,
                    )

                logger.debug(
                    "Captcha verification - ID: %s, Answer provided: %s",
                    captcha_id,
                    bool(captcha_answer),
                )

                captcha_success, captcha_error = self.handle_captcha_verification(
                    context, request, response
                )
                if not captcha_success:
                    return captcha_error

            entity_lock = self._get_entity_lock(request.phone_number)
            with entity_lock:
                success, pow_response = self.handle_pow_initialization(
                    context, request, response
                )

                if not success:
                    return pow_response

                message, expires = pow_response

                signups.create_record(
                    country_code=request.country_code, source="platforms"
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
                    "phone_number",
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

            phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
            entity_obj = find_entity(phone_number_hash=phone_number_hash)

            if entity_obj:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "Entity with this phone number already exists.",
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

    def AuthenticateEntity(self, request, context):
        """Handles the authentication of an entity."""

        response = vault_pb2.AuthenticateEntityResponse

        if hasattr(request, "phone_number"):
            request.phone_number = self.clean_phone_number(request.phone_number)

        def initiate_authentication(entity_obj):
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

            if not verify_hmac(HASHING_KEY, request.password, entity_obj.password_hash):
                register_password_attempt(entity_obj.eid)
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

            if is_captcha_enabled():
                logger.debug("Captcha verification is enabled.")
                captcha_id = getattr(request, "captcha_id", None)
                captcha_answer = getattr(request, "captcha_answer", None)

                if not captcha_id or not captcha_answer:
                    captcha_success, captcha_result = self.handle_captcha_retrieval(
                        context, response
                    )
                    if not captcha_success:
                        return captcha_result

                    captcha_id, captcha_image = captcha_result

                    return response(
                        requires_captcha=True,
                        message="Solve the captcha to proceed.",
                        captcha_id=captcha_id,
                        captcha_image=captcha_image,
                    )

                logger.debug(
                    "Captcha verification - ID: %s, Answer provided: %s",
                    captcha_id,
                    bool(captcha_answer),
                )

                captcha_success, captcha_error = self.handle_captcha_verification(
                    context, request, response
                )
                if not captcha_success:
                    return captcha_error

            entity_lock = self._get_entity_lock(request.phone_number)
            with entity_lock:
                success, pow_response = self.handle_pow_initialization(
                    context, request, response
                )
                if not success:
                    return pow_response

                message, expires = pow_response
                entity_obj.device_id = None
                entity_obj.server_state = None
                entity_obj.save()

                return response(
                    requires_ownership_proof=True,
                    message=message,
                    next_attempt_timestamp=expires,
                )

        def complete_authentication(entity_obj):
            success, pow_response = self.handle_pow_verification(
                context, request, response
            )
            if not success:
                return pow_response

            eid = entity_obj.eid.hex

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

            entity_obj.device_id = compute_device_id(
                device_id_shared_key,
                request.phone_number,
                base64.b64decode(request.client_device_id_pub_key),
            )
            entity_obj.client_publish_pub_key = request.client_publish_pub_key
            entity_obj.client_device_id_pub_key = request.client_device_id_pub_key
            entity_obj.publish_keypair = entity_publish_keypair.serialize()
            entity_obj.device_id_keypair = entity_device_id_keypair.serialize()
            entity_obj.save()

            return response(
                long_lived_token=long_lived_token,
                message="Entity authenticated successfully!",
                server_publish_pub_key=base64.b64encode(entity_publish_pub_key).decode(
                    "utf-8"
                ),
                server_device_id_pub_key=base64.b64encode(
                    entity_device_id_pub_key
                ).decode("utf-8"),
            )

        def validate_fields():
            return self.handle_request_field_validation(
                context,
                request,
                response,
                [
                    "phone_number",
                    "password",
                    "client_publish_pub_key",
                    "client_device_id_pub_key",
                ],
            )

        try:
            invalid_fields_response = validate_fields()
            if invalid_fields_response:
                return invalid_fields_response

            phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
            entity_obj = find_entity(phone_number_hash=phone_number_hash)

            if not entity_obj:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "Entity with this phone number not found.",
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

    def ListEntityStoredTokens(self, request, context):
        """Handles listing an entity's stored tokens."""

        response = vault_pb2.ListEntityStoredTokensResponse

        try:
            invalid_fields_response = self.handle_request_field_validation(
                context, request, response, ["long_lived_token"]
            )
            if invalid_fields_response:
                return invalid_fields_response

            entity_obj, llt_error_response = self.handle_long_lived_token_validation(
                request, context, response
            )
            if llt_error_response:
                return llt_error_response

            tokens = fetch_entity_tokens(
                entity=entity_obj,
                fetch_all=True,
                fields=["account_identifier", "platform", "account_tokens"],
                return_json=True,
            )

            oauth2_platforms = get_platforms_by_protocol_type("oauth2")
            fields_to_decrypt = ["account_identifier", "account_tokens"]

            for token in tokens:
                for field in fields_to_decrypt:
                    if field in token:
                        token[field] = decrypt_and_decode(token[field])

                account_tokens = json.loads(token["account_tokens"])

                if (
                    token["platform"] in oauth2_platforms
                    and not account_tokens.get("access_token")
                    and not account_tokens.get("refresh_token")
                ):
                    token["is_stored_on_device"] = True

                if request.migrate_to_device and token["platform"] in oauth2_platforms:
                    original_account_tokens = account_tokens.copy()
                    token["account_tokens"] = {
                        key: account_tokens.pop(key, "")
                        for key in ["access_token", "refresh_token", "id_token"]
                    }
                    if account_tokens != original_account_tokens:
                        account_identifier_hash = generate_hmac(
                            HASHING_KEY,
                            token.get("account_identifier"),
                        )

                        update_entity_tokens(
                            entity=entity_obj,
                            update_fields={
                                "account_tokens": encrypt_and_encode(
                                    json.dumps(account_tokens)
                                )
                            },
                            platform=token.get("platform"),
                            account_identifier_hash=account_identifier_hash,
                        )
                else:
                    token["account_tokens"] = {}

            logger.info("Successfully retrieved tokens.")
            return response(
                stored_tokens=tokens, message="Tokens retrieved successfully."
            )

        except Exception as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                e,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                error_type="UNKNOWN",
            )

    def DeleteEntity(self, request, context):
        """Handles deleting an entity"""

        response = vault_pb2.DeleteEntityResponse

        def validate_fields():
            return self.handle_request_field_validation(
                context, request, response, ["long_lived_token"]
            )

        def fetch_stored_tokens(entity_obj):
            stored_tokens = fetch_entity_tokens(
                entity=entity_obj,
                fetch_all=True,
                fields=["account_identifier", "platform"],
                return_json=True,
            )
            for token in stored_tokens:
                for field in ["account_identifier"]:
                    if field in token:
                        token[field] = decrypt_and_decode(token[field])

            if stored_tokens:
                token_info = [
                    {
                        "account_identifier": token.get("account_identifier"),
                        "platform": token.get("platform"),
                    }
                    for token in stored_tokens
                ]

                token_details = "; ".join(
                    str(
                        {
                            "account_identifier": token["account_identifier"],
                            "platform": token["platform"],
                        }
                    )
                    for token in token_info
                )

                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    f"You cannot delete entity because it still has stored tokens. "
                    f"Revoke stored tokens with the following platforms and try again: "
                    f"{token_details}.",
                    grpc.StatusCode.FAILED_PRECONDITION,
                )

            return None

        try:
            invalid_fields_response = validate_fields()
            if invalid_fields_response:
                return invalid_fields_response

            entity_obj, llt_error_response = self.handle_long_lived_token_validation(
                request, context, response
            )
            if llt_error_response:
                return llt_error_response

            stored_tokens = fetch_stored_tokens(entity_obj)
            if stored_tokens:
                return stored_tokens

            entity_obj.delete_instance()
            clear_keystore(entity_obj.eid.hex)

            logger.info("Successfully deleted entity %s", entity_obj.eid)

            return response(
                message="Entity deleted successfully.",
                success=True,
            )

        except Exception as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                e,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                error_type="UNKNOWN",
            )

    def ResetPassword(self, request, context):
        """Handles resetting an entity's password."""

        response = vault_pb2.ResetPasswordResponse

        def initiate_reset(entity_obj):
            if is_captcha_enabled():
                logger.debug("Captcha verification is enabled.")
                captcha_id = getattr(request, "captcha_id", None)
                captcha_answer = getattr(request, "captcha_answer", None)

                if not captcha_id or not captcha_answer:
                    captcha_success, captcha_result = self.handle_captcha_retrieval(
                        context, response
                    )
                    if not captcha_success:
                        return captcha_result

                    captcha_id, captcha_image = captcha_result

                    return response(
                        requires_captcha=True,
                        message="Solve the captcha to proceed.",
                        captcha_id=captcha_id,
                        captcha_image=captcha_image,
                    )

                logger.debug(
                    "Captcha verification - ID: %s, Answer provided: %s",
                    captcha_id,
                    bool(captcha_answer),
                )

                captcha_success, captcha_error = self.handle_captcha_verification(
                    context, request, response
                )
                if not captcha_success:
                    return captcha_error

            entity_lock = self._get_entity_lock(request.phone_number)
            with entity_lock:
                success, pow_response = self.handle_pow_initialization(
                    context, request, response
                )
                if not success:
                    return pow_response

                message, expires = pow_response
                entity_obj.device_id = None
                entity_obj.server_state = None
                entity_obj.save()

                return response(
                    requires_ownership_proof=True,
                    message=message,
                    next_attempt_timestamp=expires,
                )

        def complete_reset(entity_obj):
            success, pow_response = self.handle_pow_verification(
                context, request, response
            )
            if not success:
                return pow_response

            eid = entity_obj.eid.hex
            password_hash = generate_hmac(HASHING_KEY, request.new_password)

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
            entity_obj.device_id = compute_device_id(
                device_id_shared_key,
                request.phone_number,
                base64.b64decode(request.client_device_id_pub_key),
            )
            entity_obj.client_publish_pub_key = request.client_publish_pub_key
            entity_obj.client_device_id_pub_key = request.client_device_id_pub_key
            entity_obj.publish_keypair = entity_publish_keypair.serialize()
            entity_obj.device_id_keypair = entity_device_id_keypair.serialize()
            entity_obj.save()

            return response(
                long_lived_token=long_lived_token,
                message="Password reset successfully!",
                server_publish_pub_key=base64.b64encode(entity_publish_pub_key).decode(
                    "utf-8"
                ),
                server_device_id_pub_key=base64.b64encode(
                    entity_device_id_pub_key
                ).decode("utf-8"),
            )

        def validate_fields():
            invalid_fields = self.handle_request_field_validation(
                context,
                request,
                response,
                [
                    "phone_number",
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

            phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
            entity_obj = find_entity(phone_number_hash=phone_number_hash)

            if not entity_obj:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "Entity with this phone number not found.",
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

    def UpdateEntityPassword(self, request, context):
        """Handles changing an entity's password."""

        response = vault_pb2.UpdateEntityPasswordResponse

        def validate_fields():
            invalid_fields = self.handle_request_field_validation(
                context,
                request,
                response,
                [
                    "long_lived_token",
                    "current_password",
                    "new_password",
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

            entity_obj, llt_error_response = self.handle_long_lived_token_validation(
                request, context, response
            )
            if llt_error_response:
                return llt_error_response

            if is_rate_limited(entity_obj.eid):
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "Too many password attempts. Please wait and try again later.",
                    grpc.StatusCode.UNAVAILABLE,
                )

            if not verify_hmac(
                HASHING_KEY, request.current_password, entity_obj.password_hash
            ):
                register_password_attempt(entity_obj.eid)
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "The current password you entered is incorrect. Please try again.",
                    grpc.StatusCode.UNAUTHENTICATED,
                )

            clear_rate_limit(entity_obj.eid)
            new_password_hash = generate_hmac(HASHING_KEY, request.new_password)

            entity_obj.password_hash = new_password_hash
            entity_obj.device_id = None
            entity_obj.client_publish_pub_key = None
            entity_obj.client_device_id_pub_key = None
            entity_obj.publish_keypair = None
            entity_obj.device_id_keypair = None
            entity_obj.save()

            return response(message="Password updated successfully.", success=True)

        except Exception as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                e,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                error_type="UNKNOWN",
            )
