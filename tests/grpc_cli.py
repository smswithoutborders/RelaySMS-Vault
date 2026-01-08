"""CLI tool for testing gRPC Vault methods"""

import argparse
import os
import secrets
import sys

import grpc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from protos.v2 import vault_pb2 as vault_pb2_v2
from protos.v2 import vault_pb2_grpc as vault_pb2_grpc_v2


def generate_x25519_key():
    """Generate X25519 public key bytes"""
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key()
    return public.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def print_response(response):
    """Pretty print gRPC response"""
    print("\n" + "=" * 60)
    print("RESPONSE:")
    print("=" * 60)
    for field in response.DESCRIPTOR.fields:
        value = getattr(response, field.name)
        if value or isinstance(value, bool):
            print(f"  {field.name}: {value}")
    print("=" * 60 + "\n")


def create_entity_v2(stub, args):
    """Create entity (v2)"""
    print("\n>>> CreateEntity V2 <<<\n")

    print(">>> Initiating (sending OTP)...")
    request = vault_pb2_v2.CreateEntityRequest(
        country_code=args.country,
        phone_number=args.phone or "",
        email_address=args.email or "",
        password=args.password,
        ownership_proof_response="",
        captcha_token="",
        client_id_pub_key=generate_x25519_key(),
        client_ratchet_pub_key=generate_x25519_key(),
        client_nonce=secrets.token_bytes(16),
    )

    response = stub.CreateEntity(request)
    print_response(response)

    if not response.requires_ownership_proof:
        print("Entity created without OTP, Something went wrong?")
        return

    otp = input("Enter OTP code: ").strip()
    print("\n>>> Completing creation with OTP...")

    request = vault_pb2_v2.CreateEntityRequest(
        phone_number=args.phone or "",
        email_address=args.email or "",
        ownership_proof_response=otp,
    )

    response = stub.CreateEntity(request)
    print_response(response)
    print("Entity created successfully")


def main():
    parser = argparse.ArgumentParser(description="gRPC Vault API Testing Tool")

    parser.add_argument("method", choices=["create"], help="Method to test")
    parser.add_argument(
        "--version",
        "-v",
        choices=["v1", "v2"],
        default="v2",
        help="API version (default: v2)",
    )
    parser.add_argument("--phone", "-p", help="Phone number")
    parser.add_argument("--email", "-e", help="Email address")
    parser.add_argument("--password", "-pw", required=True, help="Password")
    parser.add_argument(
        "--country", "-c", default="CM", help="Country code (default: CM)"
    )
    parser.add_argument(
        "--host", default=os.getenv("GRPC_HOST", "localhost"), help="gRPC host"
    )
    parser.add_argument(
        "--port", default=os.getenv("GRPC_PORT", "8000"), help="gRPC port"
    )

    args = parser.parse_args()

    if not args.phone and not args.email:
        parser.error("Either --phone or --email is required")

    address = f"{args.host}:{args.port}"
    print(f"\nConnecting to {address}...")

    channel = grpc.insecure_channel(address)

    try:
        if args.version == "v2":
            stub = vault_pb2_grpc_v2.EntityStub(channel)

            if args.method == "create":
                create_entity_v2(stub, args)

        else:  # v1
            print("V1 methods not implemented yet")

    except grpc.RpcError as e:
        print(f"\n✗ gRPC Error: [{e.code()}]")
        print(f"   {e.details()}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nCancelled by user")
        sys.exit(0)
    finally:
        channel.close()


if __name__ == "__main__":
    main()
