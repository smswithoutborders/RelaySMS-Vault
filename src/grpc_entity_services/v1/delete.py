# SPDX-License-Identifier: GPL-3.0-only
"""Delete Entity gRPC service implementation"""

import grpc

from base_logger import get_logger
from protos.v1 import vault_pb2
from src import stats
from src.tokens import fetch_entity_tokens
from src.types import ContactType, EntityOrigin, StatsEventStage, StatsEventType
from src.utils import clear_keystore, decode_and_decrypt

logger = get_logger(__name__)


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
                    token[field] = decode_and_decrypt(token[field])

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

        identifier_type = (
            ContactType.EMAIL if entity_obj.email_hash else ContactType.PHONE
        )
        country_code = decode_and_decrypt(entity_obj.country_code)
        origin = entity_obj.origin or EntityOrigin.WEB.value

        stats.create(
            event_type=StatsEventType.DELETE_ACCOUNT,
            country_code=country_code,
            identifier_type=identifier_type,
            origin=EntityOrigin(origin),
            event_stage=StatsEventStage.COMPLETE,
        )

        clear_keystore(entity_obj.eid.hex)

        logger.info("Successfully deleted entity.")

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
