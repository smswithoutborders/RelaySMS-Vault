# Specifications

## Table of Contents

1. [Long-Lived Tokens (LLTs)](#1-long-lived-tokens-llts)
   - [Purpose](#purpose)
   - [Usage](#usage)
     - [Generating LLTs](#1-generating-llts)
     - [Retrieving the LLT from Ciphertext](#2-retrieving-the-llt-from-ciphertext)
   - [Code Example (Python)](#code-example-python)
2. [Device ID](#2-device-id)
   - [Purpose](#purpose-1)
   - [Usage](#usage-1)
     - [Generating Device ID](#1-generating-device-id)
   - [Code Example (Python)](#code-example-python-1)
3. [Auth Phrase](#3-auth-phrase)

## 1. Long-Lived Tokens (LLTs)

### Purpose

Long-Lived Tokens (LLTs) provide a secure mechanism for managing user sessions
and access control within the vault. They authenticate users and grant access
for a predefined duration, reducing the need for frequent logins.

### Usage

#### 1. Generating LLTs

- **JWT Creation**: A JSON Web Token (JWT) is created containing user
  information, signed using the `HS256` algorithm. The secret key used for
  signing is the `device_id shared secret key` (URL-safe base64-encoded)
  obtained from the `X25519` handshake between the client and the vault.

  - **Payload**: The JWT payload includes:
    - `entity_id (eid)`
    - `issuer (iss)`
    - `issued_at (iat)`
    - `expiration_time (exp)`

- **Encryption**: The generated JWT is symmetrically encrypted using
  [Fernet (symmetric encryption)](https://cryptography.io/en/latest/fernet/).
  The Fernet key used for encryption is the `device_id shared secret key`
  (URL-safe base64-encoded) obtained from the `X25519` handshake between the
  client and the vault.

The two-step process for generating LLTs ensures the JWT is signed and then
encrypted. This encryption protects the token content from unauthorized access.
Even if intercepted, the token cannot be used without the client's device, which
can perform an `X25519` handshake with the vault.

#### 2. Retrieving the LLT from Ciphertext

- **Decrypting**: Upon successful authentication, the user obtains an LLT
  ciphertext, which must be decrypted to access the plaintext LLT. Decryption is
  performed using
  [Fernet (symmetric encryption)](https://cryptography.io/en/latest/fernet/).
  The Fernet key used is the `device_id shared secret key` (URL-safe
  base64-encoded) obtained from the `X25519` handshake between the client and
  the vault.
- **Plaintext LLT**: The plaintext LLT is used for subsequent requests to the
  vault. This LLT contains user identification information and is signed to
  prevent tampering.

> [!NOTE]
>
> It is recommended not to store the plaintext LLT. Instead, the client should
> decrypt the LLT ciphertext on-demand using the device ID shared secret key
> obtained from the X25519 handshake. This prevents unauthorized access to the
> plaintext LLT, even if the client device is compromised.

### Code Example (Python)

**Generating LLTs**

```python
import base64
from cryptography.fernet import Fernet
from jwt import JWT, jwk_from_dict
from jwt.utils import get_int_from_datetime
from datetime import datetime, timedelta

# The entity ID
eid = 'entity_id'
# Device ID shared secret key obtained from the X25519 handshake
key = b'shared_secret_key'

# Create the JWT payload
payload = {
    "eid": eid,
    "iss": "https://smswithoutborders.com",
    "iat": get_int_from_datetime(datetime.now()),
    "exp": get_int_from_datetime(datetime.now() + timedelta(minutes=5)),
}

# Create the signing key
signing_key = jwk_from_dict({
    "kty": "oct",
    "k": base64.urlsafe_b64encode(key).decode("utf-8")
})

# Encode the JWT
token_obj = JWT()
llt = token_obj.encode(payload, signing_key, alg="HS256")

# Encrypt the JWT using Fernet
fernet = Fernet(base64.urlsafe_b64encode(key))
llt_ciphertext = fernet.encrypt(llt.encode("utf-8"))

# Return the encrypted LLT
print(base64.b64encode(llt_ciphertext).decode("utf-8"))
```

**Retrieving the LLT from Ciphertext**

```python
import base64
from cryptography.fernet import Fernet

# Obtained from successful authentication
llt_ciphertext = 'encrypted_llt'
# Device ID shared secret key obtained from the X25519 handshake
key = b'shared_secret_key'

# Decrypt the LLT using Fernet
fernet = Fernet(base64.urlsafe_b64encode(key))
llt_plaintext = fernet.decrypt(base64.b64decode(llt_ciphertext)).decode("utf-8")

# Return the decrypted LLT
print(llt_plaintext)
```

## 2. Device ID

### Purpose

The device ID is a unique identifier for a device which can be used to identify
an entity other than their phone number or email address. This is useful as entities can use
other phone numbers other than the one used to create their account with an
authenticated device to be able to publish messages with RelaySMS.

### Usage

#### 1. Generating Device ID:

- **Hashing**: An `HMAC` with the `SHA-256` hash algorithm is used to hash a combination of the entity's `identifier` (phone number in [E.164 format](https://en.wikipedia.org/wiki/E.164), e.g., +237123456789, or email address) and the entity's `device ID public key` (in bytes) used for the `X25519` handshake between the client and the vault. The `device_id` shared secret key obtained from the `X25519` handshake between the client and the vault is then used as the `HMAC` key for hashing the combination `(identifier + public_key_bytes)`. The resulting bytes of the hash then become the computed device ID.

> [!NOTE]
>
> It is recommended not to store the computed device ID. Instead, it should be computed on-demand on the authorized device. This prevents unauthorized access to the device ID, even if the client device is compromised.

### Code Example (Python)

```python
import hmac
import hashlib

def compute_device_id(secret_key: bytes, identifier: str, public_key: bytes) -> bytes:
    """
    Compute a device ID using HMAC and SHA-256.

    Args:
        secret_key (bytes): The secret key used for HMAC.
        identifier (str): The identifier (phone number or email) to be included in the HMAC input.
        public_key (bytes): The public key to be included in the HMAC input.

    Returns:
        bytes: The bytes representation of the HMAC digest.
    """
    # Combine identifier and public key
    combined_input = identifier.encode("utf-8") + public_key
    # Compute HMAC with SHA-256
    hmac_object = hmac.new(secret_key, combined_input, hashlib.sha256)
    # Return bytes representation of HMAC digest
    return hmac_object.digest()
```

## 3. Auth-Phrase

```python
auth_phrase = (
        bytes([len(server_publish_pub_key)])  # Length of public key
        + server_publish_pub_key  # Public key
    )
print(base64.b64encode(auth_phrase).decode("utf-8"))
```

- **Public Key Length**: The first byte indicates the length of the public key.
- **Public Key**: The actual server's public key.

The SMS message is formatted as follows:

```
RelaySMS Please paste this entire message in your RelaySMS app
<otp_code> <auth_phrase>
```
