"""Test module for entity grpc service."""

import os
from datetime import datetime, timedelta
import base64
import grpc
import pytest
from peewee import SqliteDatabase
from grpc_testing import server_from_dictionary, strict_real_time

import vault_pb2

from src.utils import (
    create_tables,
    set_configs,
    get_configs,
    generate_eid,
    load_key,
    generate_keypair_and_public_key,
    get_shared_key,
    decode_and_decrypt,
)
from src.crypto import generate_hmac


@pytest.fixture(scope="session")
def session_temp_dir(tmp_path_factory):
    """Fixture to create a persistent temporary directory for the session."""
    return tmp_path_factory.mktemp("session_temp_data")


@pytest.fixture(autouse=True)
def configure_test_environment(session_temp_dir):
    """Fixture for setting the keystore path, generating
    key paths for hashing and encryption, and setting
    the application mode to testing.
    """
    set_configs("MODE", "testing")
    set_configs("MOCK_OTP", True)
    set_configs("KEYSTORE_PATH", str(session_temp_dir))

    hashing_key_path = session_temp_dir / "hash.key"
    encryption_key_path = session_temp_dir / "encrypt.key"

    with open(hashing_key_path, "w", encoding="utf-8") as hash_file:
        hash_file.write(
            "9b5e8d7c6a2b1e3f4d6c7a5b9c8d7e6f5a4b3c2d1e3f6b4a7c8d9e5f7a8b6c4"
        )

    with open(encryption_key_path, "w", encoding="utf-8") as encrypt_file:
        encrypt_file.write(
            "3a1f7c1b4e6578379a87e2bfc3d4a76f8b29a6f4d8e5c9a8b3f7a6c2d4e5f8a7"
        )

    set_configs("HMAC_KEY_FILE", str(hashing_key_path))
    set_configs("DATA_ENCRYPTION_KEY_PRIMARY_FILE", str(encryption_key_path))


@pytest.fixture(autouse=True)
def setup_teardown_database(tmp_path, configure_test_environment):
    """Fixture for setting up and tearing down the test database."""
    from src.db_models import Entity, OTPRateLimit

    db_path = tmp_path / "test.db"
    test_db = SqliteDatabase(db_path)
    test_db.bind([Entity, OTPRateLimit])
    test_db.connect()
    create_tables([Entity, OTPRateLimit])

    yield

    test_db.drop_tables([Entity])
    test_db.close()


@pytest.fixture()
def grpc_server_mock(configure_test_environment):
    """Fixture for mocking the gRPC server."""
    from src.grpc_entity_service import EntityService

    servicers = {vault_pb2.DESCRIPTOR.services_by_name["Entity"]: EntityService()}
    test_server = server_from_dictionary(servicers, strict_real_time())
    return test_server


def test_entity_initiate_creation_success(grpc_server_mock):
    "Test case for the successful initiation of entity creation."

    request_data = {"phone_number": "+237123456789"}
    request = vault_pb2.CreateEntityRequest(**request_data)

    create_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "CreateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    response, _, code, _ = create_entity_method.termination()

    assert code == grpc.StatusCode.OK
    assert response.requires_ownership_proof is True
    assert isinstance(response.next_attempt_timestamp, int)
    assert "OTP sent successfully." in response.message


def test_entity_initiate_creation_rate_limited(grpc_server_mock):
    "Test case for rate limited initiation of entity creation."
    from src.db_models import OTPRateLimit

    request_data = {"phone_number": "+237123456789"}

    OTPRateLimit.create(
        phone_number=request_data["phone_number"],
        attempt_count=1,
        date_expires=datetime.now() + timedelta(minutes=15),
    )

    request = vault_pb2.CreateEntityRequest(**request_data)

    create_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "CreateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    _, _, code, details = create_entity_method.termination()

    assert code == grpc.StatusCode.INVALID_ARGUMENT
    assert "Too many OTP requests. Please try again later." in details


def test_entity_creation_missing_fields(grpc_server_mock):
    """Test case for missing required fields in entity creation."""
    request_data = {}
    request = vault_pb2.CreateEntityRequest(**request_data)

    create_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "CreateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    _, _, code, details = create_entity_method.termination()

    assert code == grpc.StatusCode.INVALID_ARGUMENT
    assert "Missing required fields:" in details


def test_entity_creation_already_exists(grpc_server_mock):
    """Test case for creating an entity that already exists."""
    from src.db_models import Entity

    request_data = {"phone_number": "+237123456789"}
    hash_key = load_key(get_configs("HMAC_KEY_FILE"), 32)
    phone_number_hash = generate_hmac(hash_key, request_data["phone_number"])

    Entity.create(
        phone_number_hash=phone_number_hash,
        eid=generate_eid(phone_number_hash),
        country_code="CM",
        password_hash="hashed_password",
    )

    request = vault_pb2.CreateEntityRequest(**request_data)

    create_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "CreateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    _, _, code, details = create_entity_method.termination()

    assert code == grpc.StatusCode.ALREADY_EXISTS
    assert (
        details
        == f"Entity with phone number `{request_data['phone_number']}` already exists."
    )


def test_entity_complete_creation_invalid_proof(grpc_server_mock):
    """Test case for invalid proof during entity creation."""
    request_data = {
        "phone_number": "+237123456789",
        "ownership_proof_response": "12346",
        "country_code": "CM",
        "password": "password",
        "client_publish_pub_key": base64.b64encode(b"\x82" * 32).decode("utf-8"),
        "client_device_id_pub_key": base64.b64encode(b"\x82" * 32).decode("utf-8"),
    }

    request = vault_pb2.CreateEntityRequest(**request_data)

    create_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "CreateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    _, _, code, details = create_entity_method.termination()

    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "Invalid OTP" in details


def test_entity_complete_creation_success(grpc_server_mock):
    """Test case for successful completion of entity creation."""
    from src.db_models import Entity

    # Define paths for client keystores
    client_keystore_publish = os.path.join(
        get_configs("KEYSTORE_PATH"), "client_publish.db"
    )
    client_keystore_device_id = os.path.join(
        get_configs("KEYSTORE_PATH"), "client_device_id.db"
    )

    # Generate key pairs and public keys for client
    client_publish_keypair, client_publish_pub_key = generate_keypair_and_public_key(
        client_keystore_publish
    )
    client_device_id_keypair, client_device_id_pub_key = (
        generate_keypair_and_public_key(client_keystore_device_id)
    )

    request_data = {
        "phone_number": "+237123456789",
        "ownership_proof_response": "123456",
        "country_code": "CM",
        "password": "Password@1234",
        "client_publish_pub_key": base64.b64encode(client_publish_pub_key).decode(
            "utf-8"
        ),
        "client_device_id_pub_key": base64.b64encode(client_device_id_pub_key).decode(
            "utf-8"
        ),
    }

    request = vault_pb2.CreateEntityRequest(**request_data)

    create_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "CreateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=3,
    )

    response, _, code, _ = create_entity_method.termination()

    # Generate shared keys for client
    client_publish_shared_key = get_shared_key(
        client_keystore_publish,
        client_publish_keypair.pnt_keystore,
        client_publish_keypair.secret_key,
        base64.b64decode(response.server_publish_pub_key),
    )

    client_device_id_shared_key = get_shared_key(
        client_keystore_device_id,
        client_device_id_keypair.pnt_keystore,
        client_device_id_keypair.secret_key,
        base64.b64decode(response.server_device_id_pub_key),
    )

    hash_key = load_key(get_configs("HMAC_KEY_FILE"), 32)
    phone_number_hash = generate_hmac(hash_key, request_data["phone_number"])

    entity_obj = Entity.get(Entity.phone_number_hash == phone_number_hash)

    server_keystore_publish = os.path.join(
        get_configs("KEYSTORE_PATH"), f"{entity_obj.eid.hex}_publish.db"
    )
    server_keystore_device_id = os.path.join(
        get_configs("KEYSTORE_PATH"), f"{entity_obj.eid.hex}_device_id.db"
    )

    # Decrypt and decode server crypto metadata
    server_crypto_metadata = load_crypto_metadata(
        decode_and_decrypt(entity_obj.server_crypto_metadata)
    )
    server_publish_keypair = server_crypto_metadata.publish_keypair
    server_device_id_keypair = server_crypto_metadata.device_id_keypair

    # Generate shared keys for server
    server_publish_shared_key = get_shared_key(
        server_keystore_publish,
        server_publish_keypair.pnt_keystore,
        server_publish_keypair.secret_key,
        base64.b64decode(entity_obj.client_publish_pub_key),
    )
    server_device_id_shared_key = get_shared_key(
        server_keystore_device_id,
        server_device_id_keypair.pnt_keystore,
        server_device_id_keypair.secret_key,
        base64.b64decode(entity_obj.client_device_id_pub_key),
    )

    assert code == grpc.StatusCode.OK
    assert response.message == "Entity created successfully"
    assert isinstance(response.long_lived_token, str)
    assert isinstance(response.server_publish_pub_key, str)
    assert isinstance(response.server_device_id_pub_key, str)
    assert client_publish_shared_key == server_publish_shared_key
    assert client_device_id_shared_key == server_device_id_shared_key


def test_entity_complete_creation_invalid_public_keys(grpc_server_mock):
    """Test case for entity creation with invalid public keys."""
    request_data = {
        "phone_number": "+237123456789",
        "ownership_proof_response": "123456",
        "country_code": "CM",
        "password": "Password@1234",
        "client_publish_pub_key": "invalid_key",
        "client_device_id_pub_key": "invalid_key",
    }

    request = vault_pb2.CreateEntityRequest(**request_data)

    create_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "CreateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    _, _, code, details = create_entity_method.termination()

    assert code == grpc.StatusCode.INVALID_ARGUMENT
    assert "Invalid fields:" in details


def test_entity_initiate_authentication_success(grpc_server_mock):
    """Test case for successful initiation of entity authentication."""
    from src.db_models import Entity

    request_data = {"phone_number": "+237123456789", "password": "Password@1234"}
    hash_key = load_key(get_configs("HMAC_KEY_FILE"), 32)
    phone_number_hash = generate_hmac(hash_key, request_data["phone_number"])

    Entity.create(
        phone_number_hash=phone_number_hash,
        eid=generate_eid(phone_number_hash),
        country_code="CM",
        password_hash=generate_hmac(hash_key, request_data["password"]),
    )

    request = vault_pb2.AuthenticateEntityRequest(**request_data)

    authenticate_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "AuthenticateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    response, _, code, _ = authenticate_entity_method.termination()

    assert code == grpc.StatusCode.OK
    assert response.requires_ownership_proof is True
    assert isinstance(response.next_attempt_timestamp, int)
    assert "OTP sent successfully." in response.message


def test_entity_complete_authentication_success(grpc_server_mock):
    """Test case for successful completion of entity authentication."""
    from src.db_models import Entity

    request_data = {
        "phone_number": "+237123456789",
        "password": "Password@1234",
        "ownership_proof_response": "123456",
        "client_publish_pub_key": base64.b64encode(b"\x82" * 32).decode("utf-8"),
        "client_device_id_pub_key": base64.b64encode(b"\x82" * 32).decode("utf-8"),
    }
    hash_key = load_key(get_configs("HMAC_KEY_FILE"), 32)
    phone_number_hash = generate_hmac(hash_key, request_data["phone_number"])

    Entity.create(
        phone_number_hash=phone_number_hash,
        eid=generate_eid(phone_number_hash),
        country_code="CM",
        password_hash=generate_hmac(hash_key, request_data["password"]),
    )

    request = vault_pb2.AuthenticateEntityRequest(**request_data)

    authenticate_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "AuthenticateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=3,
    )

    response, _, code, _ = authenticate_entity_method.termination()

    assert code == grpc.StatusCode.OK
    assert response.message == "Entity authenticated successfully!"
    assert isinstance(response.long_lived_token, str)
    assert isinstance(response.server_publish_pub_key, str)
    assert isinstance(response.server_device_id_pub_key, str)


def test_entity_authenticate_missing_fields(grpc_server_mock):
    """Test case for missing required fields in entity authentication."""
    request_data = {}
    request = vault_pb2.AuthenticateEntityRequest(**request_data)

    authenticate_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "AuthenticateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    _, _, code, details = authenticate_entity_method.termination()

    assert code == grpc.StatusCode.INVALID_ARGUMENT
    assert "Missing required fields:" in details


def test_entity_authenticate_incorrect_password(grpc_server_mock):
    """Test case for incorrect password during entity authentication."""
    from src.db_models import Entity

    request_data = {"phone_number": "+237123456789", "password": "Password@123"}
    hash_key = load_key(get_configs("HMAC_KEY_FILE"), 32)
    phone_number_hash = generate_hmac(hash_key, request_data["phone_number"])

    Entity.create(
        phone_number_hash=phone_number_hash,
        eid=generate_eid(phone_number_hash),
        country_code="CM",
        password_hash=generate_hmac(hash_key, "Password@1234"),
    )

    request = vault_pb2.AuthenticateEntityRequest(**request_data)

    authenticate_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "AuthenticateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    _, _, code, details = authenticate_entity_method.termination()

    assert code == grpc.StatusCode.UNAUTHENTICATED
    assert "Incorrect credentials." in details


def test_entity_complete_authentication_invalid_public_keys(grpc_server_mock):
    """Test case for entity authentication with invalid public keys."""
    from src.db_models import Entity

    request_data = {
        "phone_number": "+237123456789",
        "password": "Password@1234",
        "ownership_proof_response": "123456",
        "client_publish_pub_key": "invalid_key",
        "client_device_id_pub_key": "invalid_key",
    }
    hash_key = load_key(get_configs("HMAC_KEY_FILE"), 32)
    phone_number_hash = generate_hmac(hash_key, request_data["phone_number"])

    Entity.create(
        phone_number_hash=phone_number_hash,
        eid=generate_eid(phone_number_hash),
        country_code="CM",
        password_hash=generate_hmac(hash_key, request_data["password"]),
    )

    request = vault_pb2.AuthenticateEntityRequest(**request_data)

    authenticate_entity_method = grpc_server_mock.invoke_unary_unary(
        method_descriptor=(
            vault_pb2.DESCRIPTOR.services_by_name["Entity"].methods_by_name[
                "AuthenticateEntity"
            ]
        ),
        invocation_metadata={},
        request=request,
        timeout=1,
    )

    _, _, code, details = authenticate_entity_method.termination()

    assert code == grpc.StatusCode.INVALID_ARGUMENT
    assert "Invalid fields:" in details
