"""
Module for handling encryption, decryption, encoding, and decoding of RelaySMS payloads.
"""

import base64
import struct

from smswithoutborders_libsig.keypairs import x25519
from smswithoutborders_libsig.ratchets import HEADERS, Ratchets, States

from base_logger import get_logger

logger = get_logger(__name__)


def decrypt_payload(
    encrypted_content: bytes,
    server_identity_keypair: x25519,
    ratchet_header: bytes,
    server_state: bytes,
    server_ratchet_keypair=None,
    client_ratchet_pub_key=None,
    server_identity_private=None,
    client_nonce=None,
    server_nonce=None,
):
    """
    Decrypts a RelaySMS payload.

    Args:
        encrypted_content (bytes): Encrypted content to decrypt.
        server_identity_keypair (x25519): Server's identity keypair.
        ratchet_header (bytes): Ratchet header.
        server_state (bytes): Current state of the server-side ratchet.
        server_ratchet_keypair (x25519, optional): Server ratchet keypair for root key generation.
        client_ratchet_pub_key (bytes, optional): Client's ratchet public key.
        server_identity_private (bytes, optional): Server's identity private key.
        client_nonce (bytes, optional): Client nonce.
        server_nonce (bytes, optional): Server nonce.

    Returns:
        tuple:
            - plaintext (bytes): Decrypted content.
            - state (States): Updated server state.
            - error (Exception or None)
    """
    logger.debug("Ciphertext: %s", encrypted_content)

    try:
        if not server_state:
            state = States()
            logger.debug("Initializing ratchet...")

            if server_identity_private is not None:
                root_key = server_ratchet_keypair.agreeWithAuthAndNonce(
                    server_identity_private,
                    client_ratchet_pub_key,
                    client_nonce,
                    server_nonce,
                )
            else:
                root_key = server_identity_keypair.agree(client_ratchet_pub_key)

            Ratchets.bob_init(state, root_key, server_identity_keypair)
        else:
            logger.debug("Deserializing state...")
            logger.debug("Current state: %s", server_state)
            state = States.deserialize_json(server_state)

        logger.debug("Deserializing header...")
        logger.debug("Current header: %s", ratchet_header)
        header = HEADERS.deserialize(ratchet_header)
        logger.debug("Decrypting content...")
        plaintext = Ratchets.decrypt(
            state=state,
            header=header,
            ciphertext=encrypted_content,
            AD=server_identity_keypair.get_public_key(),
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
