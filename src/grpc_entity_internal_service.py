"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import base64
import re
import traceback

import grpc
import phonenumbers

import vault_pb2
import vault_pb2_grpc

from src import signups
from src.entity import create_entity, find_entity
from src.tokens import fetch_entity_tokens, create_entity_token, find_token
from src.crypto import generate_hmac, decrypt_aes
from src.otp_service import send_otp, verify_otp, create_inapp_otp
from src.utils import (
    load_key,
    get_configs,
    encrypt_and_encode,
    decrypt_and_decode,
    load_keypair_object,
    get_supported_platforms,
    is_valid_x25519_public_key,
    generate_eid,
    clear_keystore,
    generate_keypair_and_public_key,
)
from src.long_lived_token import verify_llt
from src.relaysms_payload import (
    decode_relay_sms_payload,
    decrypt_payload,
    encrypt_payload,
    encode_relay_sms_payload,
)
from src.db_models import StaticKeypairs
from base_logger import get_logger

logger = get_logger(__name__)

ENCRYPTION_KEY = load_key(get_configs("SHARED_KEY", strict=True), 32)
HASHING_KEY = load_key(get_configs("HASHING_SALT", strict=True), 32)
SUPPORTED_PLATFORMS = get_supported_platforms()
MOCK_OTP = get_configs("MOCK_OTP", default_value="true")
MOCK_OTP = MOCK_OTP.lower() == "true" if MOCK_OTP is not None else False


class EntityInternalService(vault_pb2_grpc.EntityInternalServicer):
    """Entity Internal Service Descriptor"""

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
            entity_device_id_keypair = load_keypair_object(entity_obj.device_id_keypair)
            entity_device_id_shared_key = entity_device_id_keypair.agree(
                base64.b64decode(entity_obj.client_device_id_pub_key),
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

    def StoreEntityToken(self, request, context):
        """Handles storing tokens for an entity"""

        response = vault_pb2.StoreEntityTokenResponse

        def check_existing_token(eid, account_identifier_hash):
            token = find_token(
                eid=eid,
                account_identifier_hash=account_identifier_hash,
                platform=request.platform,
            )

            if token:
                token.account_tokens = encrypt_and_encode(request.token)
                token.save(only=["account_tokens"])
                logger.info("Token overwritten successfully.")

                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "A token is already associated with the account identifier "
                    f"'{request.account_identifier}'.",
                    grpc.StatusCode.ALREADY_EXISTS,
                )

            return None

        try:
            invalid_fields_response = self.handle_request_field_validation(
                context,
                request,
                response,
                ["long_lived_token", "token", "platform", "account_identifier"],
            )
            if invalid_fields_response:
                return invalid_fields_response

            entity_obj, llt_error_response = self.handle_long_lived_token_validation(
                request, context, response
            )
            if llt_error_response:
                return llt_error_response

            if request.platform.lower() not in SUPPORTED_PLATFORMS:
                raise NotImplementedError(
                    f"The platform '{request.platform}' is currently not supported. "
                    "Please contact the developers for more information on when "
                    "this platform will be implemented."
                )

            account_identifier = request.account_identifier.strip()
            account_identifier_hash = generate_hmac(HASHING_KEY, account_identifier)

            existing_token = check_existing_token(
                entity_obj.eid, account_identifier_hash
            )

            if existing_token:
                return existing_token

            new_token = {
                "entity": entity_obj,
                "platform": request.platform,
                "account_identifier_hash": account_identifier_hash,
                "account_identifier": encrypt_and_encode(request.account_identifier),
                "account_tokens": encrypt_and_encode(request.token),
            }
            create_entity_token(**new_token)
            logger.info("Successfully stored tokens for %s", entity_obj.eid)

            return response(
                message="Token stored successfully.",
                success=True,
            )

        except NotImplementedError as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                str(e),
                grpc.StatusCode.UNIMPLEMENTED,
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
            publish_keypair = load_keypair_object(entity_obj.publish_keypair)
            publish_shared_key = publish_keypair.agree(
                base64.b64decode(entity_obj.client_publish_pub_key)
            )

            content_plaintext, state, decrypt_error = decrypt_payload(
                server_state=entity_obj.server_state,
                publish_shared_key=publish_shared_key,
                publish_keypair=publish_keypair,
                ratchet_header=header,
                encrypted_content=content_ciphertext,
                publish_pub_key=publish_keypair.get_public_key(),
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

            entity_obj.server_state = state.serialize()
            entity_obj.save(only=["server_state"])
            logger.info(
                "Successfully decrypted payload for %s",
                entity_obj.eid,
            )
            country_code=decrypt_and_decode(entity_obj.country_code)
            return response(
                message="Successfully decrypted payload",
                success=True,
                payload_plaintext=content_plaintext,
                country_code=country_code
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
                phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
                entity_obj = find_entity(phone_number_hash=phone_number_hash)
                if not entity_obj:
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        f"Entity associated with phone number '{request.phone_number}' not found. "
                        "Please check your phone number and try again.",
                        grpc.StatusCode.UNAUTHENTICATED,
                    )

            decoded_response, decoding_error = decode_message()
            if decoding_error:
                return decoding_error

            header, content_ciphertext = decoded_response

            return decrypt_message(entity_obj, header, content_ciphertext)

        except Exception as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                e,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                error_type="UNKNOWN",
            )

    def EncryptPayload(self, request, context):
        """Handles encrypting payload"""

        response = vault_pb2.EncryptPayloadResponse

        def validate_fields():
            return self.handle_request_field_validation(
                context,
                request,
                response,
                [("device_id", "phone_number"), "payload_plaintext"],
            )

        def encrypt_message(entity_obj):
            header, content_ciphertext, state, encrypt_error = encrypt_payload(
                server_state=entity_obj.server_state,
                client_publish_pub_key=base64.b64decode(
                    entity_obj.client_publish_pub_key
                ),
                content=request.payload_plaintext,
            )

            if encrypt_error:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    encrypt_error,
                    grpc.StatusCode.INVALID_ARGUMENT,
                    error_prefix="Error Encrypting Content",
                    error_type="UNKNOWN",
                )

            return (header, content_ciphertext, state), None

        def encode_message(header, content_ciphertext, state):
            encoded_content, encode_error = encode_relay_sms_payload(
                header, content_ciphertext
            )

            if encode_error:
                return None, self.handle_create_grpc_error_response(
                    context,
                    response,
                    encode_error,
                    grpc.StatusCode.INVALID_ARGUMENT,
                    error_prefix="Error Encoding Content",
                    error_type="UNKNOWN",
                )

            entity_obj.server_state = state.serialize()
            entity_obj.save(only=["server_state"])
            logger.info(
                "Successfully encrypted payload for %s",
                entity_obj.eid,
            )

            return response(
                message="Successfully encrypted payload.",
                payload_ciphertext=encoded_content,
                success=True,
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
                phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
                entity_obj = find_entity(phone_number_hash=phone_number_hash)
                if not entity_obj:
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        f"Entity associated with phone number '{request.phone_number}' not found. "
                        "Please check your phone number and try again.",
                        grpc.StatusCode.UNAUTHENTICATED,
                    )

            encrypted_response, encrypting_error = encrypt_message(entity_obj)
            if encrypting_error:
                return encrypting_error

            header, content_ciphertext, state = encrypted_response

            return encode_message(header, content_ciphertext, state)

        except Exception as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                e,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                error_type="UNKNOWN",
            )

    def GetEntityAccessToken(self, request, context):
        """Handles getting an entity's access token."""

        response = vault_pb2.GetEntityAccessTokenResponse

        def validate_fields():
            return self.handle_request_field_validation(
                context,
                request,
                response,
                [
                    ("device_id", "long_lived_token", "phone_number"),
                    "platform",
                    "account_identifier",
                ],
            )

        def fetch_tokens(entity_obj, account_identifier_hash):
            tokens = fetch_entity_tokens(
                entity=entity_obj,
                fields=["account_tokens"],
                return_json=True,
                platform=request.platform,
                account_identifier_hash=account_identifier_hash,
            )
            for token in tokens:
                for field in ["account_tokens"]:
                    if field in token:
                        token[field] = decrypt_and_decode(token[field])

            logger.info(
                "Successfully fetched tokens for %s",
                entity_obj.eid,
            )

            if not tokens:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "No token found with account "
                    f"identifier {request.account_identifier} for {request.platform}",
                    grpc.StatusCode.NOT_FOUND,
                )

            return response(
                message="Successfully fetched tokens.",
                success=True,
                token=tokens[0]["account_tokens"],
            )

        try:
            invalid_fields_response = validate_fields()
            if invalid_fields_response:
                return invalid_fields_response

            if request.long_lived_token:
                entity_obj, llt_error_response = (
                    self.handle_long_lived_token_validation(request, context, response)
                )
                if llt_error_response:
                    return llt_error_response

            elif request.device_id:
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
                phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
                entity_obj = find_entity(phone_number_hash=phone_number_hash)
                if not entity_obj:
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        f"Entity associated with phone number '{request.phone_number}' not found. "
                        "Please check your phone number and try again.",
                        grpc.StatusCode.UNAUTHENTICATED,
                    )

            if request.platform.lower() not in SUPPORTED_PLATFORMS:
                raise NotImplementedError(
                    f"The platform '{request.platform}' is currently not supported. "
                    "Please contact the developers for more information on when "
                    "this platform will be implemented."
                )

            account_identifier = request.account_identifier.strip()
            account_identifier_hash = generate_hmac(HASHING_KEY, account_identifier)

            return fetch_tokens(entity_obj, account_identifier_hash)

        except NotImplementedError as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                str(e),
                grpc.StatusCode.UNIMPLEMENTED,
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

    def UpdateEntityToken(self, request, context):
        """Handles updating tokens for an entity"""

        response = vault_pb2.UpdateEntityTokenResponse

        try:
            invalid_fields_response = self.handle_request_field_validation(
                context,
                request,
                response,
                [
                    ("device_id", "phone_number"),
                    "token",
                    "platform",
                    "account_identifier",
                ],
            )
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
                phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
                entity_obj = find_entity(phone_number_hash=phone_number_hash)
                if not entity_obj:
                    return self.handle_create_grpc_error_response(
                        context,
                        response,
                        f"Entity associated with phone number '{request.phone_number}' not found. "
                        "Please check your phone number and try again.",
                        grpc.StatusCode.UNAUTHENTICATED,
                    )

            account_identifier = request.account_identifier.strip()
            account_identifier_hash = generate_hmac(HASHING_KEY, account_identifier)

            existing_tokens = fetch_entity_tokens(
                entity=entity_obj,
                account_identifier_hash=account_identifier_hash,
                platform=request.platform,
            )

            if not existing_tokens:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "No token found with account "
                    f"identifier {request.account_identifier} for {request.platform}",
                    grpc.StatusCode.NOT_FOUND,
                )

            existing_tokens[0].account_tokens = encrypt_and_encode(request.token)
            existing_tokens[0].save(only=["account_tokens"])
            logger.info("Successfully updated token for %s", entity_obj.eid)

            return response(
                message="Token updated successfully.",
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

    def DeleteEntityToken(self, request, context):
        """Handles deleting tokens for an entity"""

        response = vault_pb2.DeleteEntityTokenResponse

        try:
            invalid_fields_response = self.handle_request_field_validation(
                context,
                request,
                response,
                ["long_lived_token", "platform", "account_identifier"],
            )
            if invalid_fields_response:
                return invalid_fields_response

            entity_obj, llt_error_response = self.handle_long_lived_token_validation(
                request, context, response
            )
            if llt_error_response:
                return llt_error_response

            if request.platform.lower() not in SUPPORTED_PLATFORMS:
                raise NotImplementedError(
                    f"The platform '{request.platform}' is currently not supported. "
                    "Please contact the developers for more information on when "
                    "this platform will be implemented."
                )

            account_identifier = request.account_identifier.strip()
            account_identifier_hash = generate_hmac(HASHING_KEY, account_identifier)

            existing_tokens = fetch_entity_tokens(
                entity=entity_obj,
                account_identifier_hash=account_identifier_hash,
                platform=request.platform,
            )

            if not existing_tokens:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "No token found with account "
                    f"identifier {request.account_identifier} for {request.platform}",
                    grpc.StatusCode.NOT_FOUND,
                )

            existing_tokens[0].delete_instance()

            logger.info("Successfully deleted token for %s", entity_obj.eid)

            return response(
                message="Token deleted successfully.",
                success=True,
            )

        except NotImplementedError as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                str(e),
                grpc.StatusCode.UNIMPLEMENTED,
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

    def CreateBridgeEntity(self, request, context):
        """Handles the creation of a bridge entity."""

        response = vault_pb2.CreateBridgeEntityResponse

        def complete_creation(entity_obj):
            success, message = verify_otp(
                request.phone_number,
                request.ownership_proof_response,
                use_twilio=False,
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
                entity_obj.publish_keypair = entity_publish_keypair.serialize()
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
                    "publish_keypair": entity_publish_keypair.serialize(),
                    "is_bridge_enabled": False,
                }

                create_entity(**fields)

            if MOCK_OTP:
                otp_code = "123456"
            else:
                _, otp_result = create_inapp_otp(phone_number=request.phone_number)
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

            success, message, _ = send_otp(request.phone_number, message_body)

            if not success:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    message,
                    grpc.StatusCode.INVALID_ARGUMENT,
                )

            signups.create_record(country_code=request.country_code, source="bridges")

            return response(success=True, message=message_body if MOCK_OTP else message)

        # This is for bridge_server payload version >=1
        def handle_bridge_entity_creation(phone_number_hash, eid, entity_obj=None):
            invalid_fields_response = self.handle_request_field_validation(
                context,
                request,
                response,
                [
                    "country_code",
                    "client_publish_pub_key",
                    "server_pub_key_identifier",
                    "server_pub_key_version",
                ],
            )
            if invalid_fields_response:
                return invalid_fields_response

            server_publish_keypair = StaticKeypairs.get_keypair(
                request.server_pub_key_identifier, request.server_pub_key_version
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

            server_publish_keypair_plaintext = decrypt_aes(
                ENCRYPTION_KEY,
                server_publish_keypair.keypair_bytes,
                is_bytes=True,
            )
            if entity_obj:
                new_server_pub_key = load_keypair_object(
                    server_publish_keypair_plaintext
                ).get_public_key()
                current_server_pub_key = load_keypair_object(
                    entity_obj.publish_keypair
                ).get_public_key()

                if (new_server_pub_key != current_server_pub_key) or (
                    request.client_publish_pub_key != entity_obj.client_publish_pub_key
                ):
                    logger.info(
                        "Detected new public keys. Overwriting existing keys for the entity."
                    )
                    clear_keystore(eid)
                    entity_obj.client_publish_pub_key = request.client_publish_pub_key
                    entity_obj.publish_keypair = server_publish_keypair_plaintext
                    entity_obj.server_state = None
                    entity_obj.save(
                        only=[
                            "client_publish_pub_key",
                            "publish_keypair",
                            "server_state",
                        ]
                    )
                    logger.info("Successfully reauthenticated entity.")
                    return response(
                        success=True, message="Successfully reauthenticated entity."
                    )

                logger.info("Successfully verified entity.")
                return response(success=True, message="Successfully verified entity.")

            create_entity(
                eid=eid,
                phone_number_hash=phone_number_hash,
                password_hash=None,
                country_code=encrypt_and_encode(request.country_code),
                client_publish_pub_key=request.client_publish_pub_key,
                publish_keypair=server_publish_keypair_plaintext,
                is_bridge_enabled=True,
            )
            signups.create_record(country_code=request.country_code, source="bridges")

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

            phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
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

    def AuthenticateBridgeEntity(self, request, context):
        """Handles authenticating a bridge entity."""

        response = vault_pb2.AuthenticateBridgeEntityResponse

        try:
            invalid_fields_response = self.handle_request_field_validation(
                context,
                request,
                response,
                ["phone_number"],
            )
            if invalid_fields_response:
                return invalid_fields_response

            phone_number_hash = generate_hmac(HASHING_KEY, request.phone_number)
            entity_obj = find_entity(phone_number_hash=phone_number_hash)

            if not entity_obj:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "Bridge Entity with this phone number not found.",
                    grpc.StatusCode.NOT_FOUND,
                )

            if not entity_obj.is_bridge_enabled:
                return self.handle_create_grpc_error_response(
                    context,
                    response,
                    "Bridges are not enabled for Entity with this phone number.",
                    grpc.StatusCode.UNAUTHENTICATED,
                )

            return response(success=True, message="Authentication successful.")

        except Exception as e:
            return self.handle_create_grpc_error_response(
                context,
                response,
                e,
                grpc.StatusCode.INTERNAL,
                user_msg="Oops! Something went wrong. Please try again later.",
                error_type="UNKNOWN",
            )
