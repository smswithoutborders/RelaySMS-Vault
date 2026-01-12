"""
Module for handling encryption, decryption, encoding, and decoding of RelaySMS payloads.
"""

import base64
import struct

from smswithoutborders_libsig.keypairs import x25519
from smswithoutborders_libsig.ratchets import HEADERS, Ratchets, States
from smswithoutborders_libsig.ratchetsHE import RatchetsHE

from base_logger import get_logger

logger = get_logger(__name__)


def _initialize_ratchet_state(
    server_identity_keypair: x25519,
    client_ratchet_pub_key: bytes,
    client_nonce: bytes,
    server_nonce: bytes,
    server_ratchet_keypair=None,
    client_header_pub_key=None,
    client_next_header_pub_key=None,
):
    """
    Initialize ratchet state for Bob (server).

    Args:
        server_identity_keypair (x25519): Server's identity keypair.
        client_ratchet_pub_key (bytes): Client's ratchet public key.
        client_nonce (bytes): Client nonce.
        server_nonce (bytes): Server nonce.
        server_ratchet_keypair (x25519, optional): Server ratchet keypair.
        client_header_pub_key (bytes, optional): Client's header public key.
        client_next_header_pub_key (bytes, optional): Client's next header public key.

    Returns:
        tuple: (state, root_key, header_key, next_header_key) or (state, root_key, None, None)
    """
    state = States()
    server_identity_private = server_identity_keypair.load_keystore(
        server_identity_keypair.pnt_keystore, server_identity_keypair.secret_key
    )
    if not server_ratchet_keypair:
        root_key = server_identity_keypair.agree(client_ratchet_pub_key)
        return state, root_key, None, None

    root_key, header_key, next_header_key = (
        server_ratchet_keypair.agreeWithAuthAndNonce(
            auth_private_key=server_identity_private,
            auth_public_key=None,
            header_public_key=client_header_pub_key,
            next_header_public_key=client_next_header_pub_key,
            public_key=client_ratchet_pub_key,
            nonce1=client_nonce,
            nonce2=server_nonce,
        )
    )
    return state, root_key, header_key, next_header_key


def _decrypt_with_standard_ratchet(
    state: States,
    ratchet_header: bytes,
    encrypted_content: bytes,
    associated_data: bytes,
):
    """
    Decrypt payload using standard ratchet.

    Args:
        state (States): Current ratchet state.
        ratchet_header (bytes): Serialized ratchet header.
        encrypted_content (bytes): Encrypted content.
        associated_data (bytes): Associated data for decryption.

    Returns:
        bytes: Decrypted plaintext.
    """
    logger.debug("Deserializing header...")
    logger.debug("Current header: %s", ratchet_header)
    header = HEADERS.deserialize(ratchet_header)

    logger.debug("Decrypting content...")
    plaintext = Ratchets.decrypt(
        state=state,
        header=header,
        ciphertext=encrypted_content,
        AD=associated_data,
    )
    return plaintext


def _decrypt_with_header_encrypted_ratchet(
    state: States,
    encrypted_header: bytes,
    encrypted_content: bytes,
    associated_data: bytes,
):
    """
    Decrypt payload using header-encrypted ratchet.

    Args:
        state (States): Current ratchet state.
        encrypted_header (bytes): Encrypted ratchet header.
        encrypted_content (bytes): Encrypted content.
        associated_data (bytes): Associated data for decryption.

    Returns:
        bytes: Decrypted plaintext.
    """
    logger.debug("Decrypting content with header encryption...")
    plaintext = RatchetsHE.RatchetDecryptHE(
        state=state,
        enc_header=encrypted_header,
        ciphertext=encrypted_content,
        AD=associated_data,
    )
    return plaintext


def decrypt_payload(
    encrypted_content: bytes,
    ratchet_header: bytes,
    server_state: bytes,
    server_identity_keypair: x25519,
    server_ratchet_keypair=None,
    server_nonce=None,
    client_ratchet_pub_key=None,
    client_header_pub_key=None,
    client_next_header_pub_key=None,
    client_nonce=None,
):
    """
    Decrypts a RelaySMS payload.

    Args:
        encrypted_content (bytes): Encrypted content to decrypt.
        ratchet_header (bytes): Ratchet header (encrypted or plaintext).
        server_state (bytes): Current state of the server-side ratchet.
        server_identity_keypair (x25519): Server's identity keypair.
        server_identity_private (bytes, optional): Server's identity private key.
        server_ratchet_keypair (x25519, optional): Server ratchet keypair.
        server_nonce (bytes, optional): Server nonce.
        client_ratchet_pub_key (bytes, optional): Client's ratchet public key.
        client_header_pub_key (bytes, optional): Client's header public key.
        client_next_header_pub_key (bytes, optional): Client's next header public key.
        client_nonce (bytes, optional): Client nonce.

    Returns:
        tuple:
            - plaintext (bytes): Decrypted content.
            - state (States): Updated server state.
            - error (Exception or None)
    """
    logger.debug("Ciphertext: %s", encrypted_content)

    try:
        associated_data = server_identity_keypair.get_public_key()

        if not server_state:
            use_header_encryption = all(
                [client_header_pub_key, client_next_header_pub_key]
            )
            logger.debug("Initializing ratchet...")
            state, root_key, header_key, next_header_key = _initialize_ratchet_state(
                server_identity_keypair=server_identity_keypair,
                server_ratchet_keypair=server_ratchet_keypair,
                client_ratchet_pub_key=client_ratchet_pub_key,
                client_nonce=client_nonce,
                server_nonce=server_nonce,
                client_header_pub_key=client_header_pub_key,
                client_next_header_pub_key=client_next_header_pub_key,
            )

            if use_header_encryption:
                logger.debug("Using header-encrypted ratchet initialization...")
                RatchetsHE.bob_init_HE(
                    state=state,
                    SK=root_key,
                    bob_dh_key_pair=server_ratchet_keypair,
                    shared_hka=header_key,
                    shared_nhkb=next_header_key,
                )
            else:
                logger.debug("Using standard ratchet initialization...")
                Ratchets.bob_init(state, root_key, server_identity_keypair)
        else:
            logger.debug("Deserializing state...")
            logger.debug("Current state: %s", server_state)
            state = States.deserialize_json(server_state)
            use_header_encryption = hasattr(state, "HKr")

        if use_header_encryption:
            plaintext = _decrypt_with_header_encrypted_ratchet(
                state=state,
                encrypted_header=ratchet_header,
                encrypted_content=encrypted_content,
                associated_data=associated_data,
            )
        else:
            plaintext = _decrypt_with_standard_ratchet(
                state=state,
                ratchet_header=ratchet_header,
                encrypted_content=encrypted_content,
                associated_data=associated_data,
            )

        logger.debug("Plaintext: %s", plaintext)
        return plaintext, state, None
    except Exception as e:
        return None, None, e


def encrypt_payload(server_state, client_publish_pub_key, content):
    """
    Encrypts content into a RelaySMS payload.

    Args:
        server_state (bytes): Current state of the server-side ratchet.
        client_publish_pub_key (bytes): Client's public key for encryption.
        content (str): Plaintext content to encrypt.

    Returns:
        tuple:
            - header (bytes): Serialized ratchet header.
            - content_ciphertext (bytes): Encrypted content.
            - state (bytes): Updated server state.
            - error (Exception or None)
    """
    logger.debug("Plaintext: %s", content)
    try:
        if not server_state:
            raise ValueError("Server state is not initialized.")

        logger.debug("Deserializing state...")
        logger.debug("Current state: %s", server_state)
        state = States.deserialize_json(server_state)
        logger.debug("Encrypting content...")
        header, content_ciphertext = Ratchets.encrypt(
            state=state, data=content.encode("utf-8"), AD=client_publish_pub_key
        )
        logger.debug("Current header: %s", header)
        logger.debug("Ciphertext: %s", content_ciphertext)
        return header.serialize(), content_ciphertext, state, None
    except Exception as e:
        return None, None, None, e


def decode_relay_sms_payload(content):
    """
    Decode a RelaySMS payload from a base64-encoded string.

    Args:
        content (str): Base64-encoded string representing the payload.

    Returns:
        tuple:
            - header (bytes): Ratchet header.
            - encrypted_content (bytes): Encrypted payload.
            - error (Exception or None)
    """
    try:
        logger.debug("Unpacking payload....")
        payload = base64.b64decode(content)
        len_header = struct.unpack("<i", payload[:4])[0]
        header = payload[4 : 4 + len_header]
        encrypted_content = payload[4 + len_header :]
        return header, encrypted_content, None
    except Exception as e:
        return None, None, e


def encode_relay_sms_payload(header, content_ciphertext):
    """
    Encode a RelaySMS payload to a base64-encoded string.

    Args:
        header (bytes): Ratchet header.
        content_ciphertext (bytes): Encrypted content.

    Returns:
        tuple:
            - encrypted_payload (str): Base64-encoded representation of the payload.
            - error (Exception or None)
    """
    try:
        logger.debug("Packing payload...")
        len_header = len(header)
        return (
            base64.b64encode(
                struct.pack("<i", len_header) + header + content_ciphertext
            ).decode("utf-8"),
            None,
        )
    except Exception as e:
        return None, e
