# Vault gRPC Documentation

## Table of Contents

- [Download Protocol Buffer Files](#download-protocol-buffer-files)
- [Prerequisites](#prerequisites)
- [Version 2 API](#version-2-api)
  - [v2 Public Service](#v2-public-service)
    - [v2: Create an Entity](#v2-create-an-entity)
    - [v2: Authenticate an Entity](#v2-authenticate-an-entity)
- [Version 1 API](#version-1-api)
  - [v1 Public Service](#v1-public-service)
    - [v1: Create an Entity](#v1-create-an-entity)
    - [v1: Authenticate an Entity](#v1-authenticate-an-entity)
    - [v1: List Entity Stored Tokens](#v1-list-entity-stored-tokens)
    - [v1: Delete An Entity](#v1-delete-an-entity)
    - [v1: Reset Password](#v1-reset-password)
    - [v1: Update Password](#v1-update-password)
  - [v1 Internal Service](#v1-internal-service)
    - [v1: Store Token](#v1-store-token)
    - [v1: Get Access Token](#v1-get-access-token)
    - [v1: Decrypt Payload](#v1-decrypt-payload)
    - [v1: Encrypt Payload](#v1-encrypt-payload)
    - [v1: Update Token](#v1-update-token)
    - [v1: Delete Token](#v1-delete-token)
    - [v1: Create Bridge Entity](#v1-create-bridge-entity)
    - [v1: Authenticate Bridge Entity](#v1-authenticate-bridge-entity)

## Download Protocol Buffer Files

### Version 2

```bash
curl -O -L https://raw.githubusercontent.com/smswithoutborders/RelaySMS-Vault/staging/protos/v2/vault.proto
```

**Package:** `vault.v2`  
**Service:** `Entity`

### Version 1

```bash
curl -O -L https://raw.githubusercontent.com/smswithoutborders/RelaySMS-Vault/staging/protos/v1/vault.proto
```

**Package:** `vault.v1`  
**Services:** `Entity`, `EntityInternal`

## Prerequisites

### Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

For other languages, see [Supported languages](https://grpc.io/docs/languages/).

### Compile gRPC

**For Version 2:**

```bash
python -m grpc_tools.protoc -I protos/v2 --python_out=. --grpc_python_out=. protos/v2/vault.proto
```

**For Version 1:**

```bash
python -m grpc_tools.protoc -I protos/v1 --python_out=. --grpc_python_out=. protos/v1/vault.proto
```

### Starting the Server

**Public Server:**

```bash
DATA_ENCRYPTION_KEY_PRIMARY_FILE=/path/to/encryption.key \
HMAC_KEY_FILE=/path/to/hashing.key \
KEYSTORE_PATH=/path/to/key_store \
SQLITE_DATABASE_PATH=/path/to/local.db \
GRPC_PORT=<your_port> \
GRPC_HOST=<your_host> \
python3 grpc_server.py
```

**Internal Server:**

```bash
DATA_ENCRYPTION_KEY_PRIMARY_FILE=/path/to/encryption.key \
HMAC_KEY_FILE=/path/to/hashing.key \
KEYSTORE_PATH=/path/to/key_store \
SQLITE_DATABASE_PATH=/path/to/local.db \
GRPC_INTERNAL_PORT=<your_port> \
GRPC_HOST=<your_host> \
python3 grpc_internal_server.py
```

---

## Version 2 API

**Package:** `vault.v2`  
**Service:** `Entity`

---

## v2 Public Service

Service for public entity management operations.

### v2: Create an Entity

Creates a new entity with two-step ownership verification.

#### Step 1: Initiate Creation

**Request:** `CreateEntityRequest`

| Field                  | Type   | Required | Description                                    |
| ---------------------- | ------ | -------- | ---------------------------------------------- |
| phone_number           | string | Optional | Phone number in E164 format (e.g., +237123456789) |
| email_address          | string | Optional | Email address                                  |
| country_code           | string | Yes      | ISO 3166-1 alpha-2 code (e.g., CM)            |
| password               | string | Yes      | Secure password                                |
| captcha_token          | string | Yes*     | Captcha verification token (*if captcha enabled)|
| client_id_pub_key      | bytes  | Yes      | Client identification public key               |
| client_ratchet_pub_key | bytes  | Yes      | Client ratchet public key                      |
| client_nonce           | bytes  | Yes      | Client nonce                                   |

**Response:** `CreateEntityResponse`

| Field                    | Type   | Description                                    |
| ------------------------ | ------ | ---------------------------------------------- |
| requires_ownership_proof | bool   | Whether ownership proof is required            |
| next_attempt_timestamp   | int32  | Next available time to request OTP (Unix seconds) |
| message                  | string | Response message                               |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v2/vault.proto \
<your_host>:<your_port> vault.v2.Entity/CreateEntity <<EOF
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "password": "SecurePass123!",
  "captcha_token": "captcha_token_value",
  "client_id_pub_key": "...",
  "client_ratchet_pub_key": "...",
  "client_nonce": "..."
}
EOF
```

#### Step 2: Complete Creation

**Request:** `CreateEntityRequest`

| Field                    | Type   | Required | Description                     |
| ------------------------ | ------ | -------- | ------------------------------- |
| phone_number             | string | Optional | Phone number in E164 format     |
| email_address            | string | Optional | Email address                   |
| ownership_proof_response | string | Yes      | OTP code from step 1            |

**Response:** `CreateEntityResponse`

| Field                  | Type   | Description                    |
| ---------------------- | ------ | ------------------------------ |
| long_lived_token       | string | Session token                  |
| server_ratchet_pub_key | bytes  | Server ratchet public key      |
| server_nonce           | bytes  | Server nonce                   |
| message                | string | Response message               |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v2/vault.proto \
<your_host>:<your_port> vault.v2.Entity/CreateEntity <<EOF
{
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "ownership_proof_response": "123456"
}
EOF
```

---

### v2: Authenticate an Entity

Authenticates an existing entity with two-step verification.

#### Step 1: Initiate Authentication

**Request:** `AuthenticateEntityRequest`

| Field                  | Type   | Required | Description                        |
| ---------------------- | ------ | -------- | ---------------------------------- |
| phone_number           | string | Optional | Phone number in E164 format        |
| email_address          | string | Optional | Email address                      |
| password               | string | Yes      | Entity password                    |
| captcha_token          | string | Yes*     | Captcha verification token (*if captcha enabled)|
| client_id_pub_key      | bytes  | Yes      | Client identification public key   |
| client_ratchet_pub_key | bytes  | Yes      | Client ratchet public key          |
| client_nonce           | bytes  | Yes      | Client nonce                       |

**Response:** `AuthenticateEntityResponse`

| Field                    | Type   | Description                           |
| ------------------------ | ------ | ------------------------------------- |
| requires_ownership_proof | bool   | Whether ownership proof is required   |
| requires_password_reset  | bool   | Whether password reset is required    |
| next_attempt_timestamp   | int32  | Next available time to request OTP    |
| message                  | string | Response message                      |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v2/vault.proto \
<your_host>:<your_port> vault.v2.Entity/AuthenticateEntity <<EOF
{
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "password": "SecurePass123!",
  "captcha_token": "captcha_token_value",
  "client_id_pub_key": "...",
  "client_ratchet_pub_key": "...",
  "client_nonce": "..."
}
EOF
```

#### Step 2: Complete Authentication

**Request:** `AuthenticateEntityRequest`

| Field                    | Type   | Required | Description                     |
| ------------------------ | ------ | -------- | ------------------------------- |
| phone_number             | string | Optional | Phone number in E164 format     |
| email_address            | string | Optional | Email address                   |
| ownership_proof_response | string | Yes      | OTP code from step 1            |

**Response:** `AuthenticateEntityResponse`

| Field                  | Type   | Description               |
| ---------------------- | ------ | ------------------------- |
| long_lived_token       | string | Session token             |
| server_ratchet_pub_key | bytes  | Server ratchet public key |
| server_nonce           | bytes  | Server nonce              |
| message                | string | Response message          |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v2/vault.proto \
<your_host>:<your_port> vault.v2.Entity/AuthenticateEntity <<EOF
{
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "ownership_proof_response": "123456"
}
EOF
```

---

## Version 1 API

**Package:** `vault.v1`  
**Services:** `Entity`, `EntityInternal`

---

## v1 Public Service

Service for public entity management operations.

### v1: Create an Entity

Creates a new entity with two-step ownership verification.

#### Step 1: Initiate Creation

**Request:** `CreateEntityRequest`

| Field                    | Type   | Required | Description                              |
| ------------------------ | ------ | -------- | ---------------------------------------- |
| phone_number             | string | Optional | Phone number in E164 format              |
| email_address            | string | Optional | Email address                            |
| country_code             | string | Yes      | ISO 3166-1 alpha-2 code                  |
| password                 | string | Yes      | Secure password                          |
| captcha_token            | string | Yes*     | Captcha verification token (*if captcha enabled)|
| client_publish_pub_key   | string | Yes      | X25519 public key for publishing (base64)|
| client_device_id_pub_key | string | Yes      | X25519 public key for device ID (base64) |

**Response:** `CreateEntityResponse`

| Field                    | Type   | Description                        |
| ------------------------ | ------ | ---------------------------------- |
| requires_ownership_proof | bool   | Whether ownership proof is required|
| next_attempt_timestamp   | int32  | Next available OTP request time    |
| message                  | string | Response message                   |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/CreateEntity <<EOF
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "password": "SecurePass123!",
  "captcha_token": "captcha_token_value",
  "client_publish_pub_key": "base64_x25519_publish_key",
  "client_device_id_pub_key": "base64_x25519_device_id_key"
}
EOF
```

#### Step 2: Complete Creation

**Request:** `CreateEntityRequest`

| Field                    | Type   | Required | Description                              |
| ------------------------ | ------ | -------- | ---------------------------------------- |
| phone_number             | string | Optional | Phone number in E164 format              |
| email_address            | string | Optional | Email address                            |
| country_code             | string | Yes      | ISO 3166-1 alpha-2 code                  |
| password                 | string | Yes      | Secure password                          |
| ownership_proof_response | string | Yes      | OTP code from step 1                     |
| client_publish_pub_key   | string | Yes      | X25519 public key for publishing (base64)|
| client_device_id_pub_key | string | Yes      | X25519 public key for device ID (base64) |

**Response:** `CreateEntityResponse`

| Field                    | Type   | Description                             |
| ------------------------ | ------ | --------------------------------------- |
| long_lived_token         | string | Session token                           |
| server_publish_pub_key   | string | Server X25519 publish key (base64)      |
| server_device_id_pub_key | string | Server X25519 device ID key (base64)    |
| message                  | string | Response message                        |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/CreateEntity <<EOF
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "password": "SecurePass123!",
  "ownership_proof_response": "123456",
  "client_publish_pub_key": "base64_x25519_publish_key",
  "client_device_id_pub_key": "base64_x25519_device_id_key"
}
EOF
```

---

### v1: Authenticate an Entity

Authenticates an existing entity with two-step verification.

#### Step 1: Initiate Authentication

**Request:** `AuthenticateEntityRequest`

| Field                    | Type   | Required | Description                              |
| ------------------------ | ------ | -------- | ---------------------------------------- |
| phone_number             | string | Optional | Phone number in E164 format              |
| email_address            | string | Optional | Email address                            |
| password                 | string | Yes      | Entity password                          |
| captcha_token            | string | Yes*     | Captcha verification token (*if captcha enabled)|
| client_publish_pub_key   | string | Yes      | X25519 public key for publishing (base64)|
| client_device_id_pub_key | string | Yes      | X25519 public key for device ID (base64) |

**Response:** `AuthenticateEntityResponse`

| Field                    | Type   | Description                        |
| ------------------------ | ------ | ---------------------------------- |
| requires_ownership_proof | bool   | Whether ownership proof is required|
| requires_password_reset  | bool   | Whether password reset is required |
| next_attempt_timestamp   | int32  | Next available OTP request time    |
| message                  | string | Response message                   |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/AuthenticateEntity <<EOF
{
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "password": "SecurePass123!",
  "captcha_token": "captcha_token_value",
  "client_publish_pub_key": "base64_x25519_publish_key",
  "client_device_id_pub_key": "base64_x25519_device_id_key"
}
EOF
```

#### Step 2: Complete Authentication

**Request:** `AuthenticateEntityRequest`

| Field                    | Type   | Required | Description                              |
| ------------------------ | ------ | -------- | ---------------------------------------- |
| phone_number             | string | Optional | Phone number in E164 format              |
| email_address            | string | Optional | Email address                            |
| password                 | string | Yes      | Entity password                          |
| ownership_proof_response | string | Yes      | OTP code from step 1                     |
| client_publish_pub_key   | string | Yes      | X25519 public key for publishing (base64)|
| client_device_id_pub_key | string | Yes      | X25519 public key for device ID (base64) |

**Response:** `AuthenticateEntityResponse`

| Field                    | Type   | Description                          |
| ------------------------ | ------ | ------------------------------------ |
| long_lived_token         | string | Session token                        |
| server_publish_pub_key   | string | Server X25519 publish key (base64)   |
| server_device_id_pub_key | string | Server X25519 device ID key (base64) |
| message                  | string | Response message                     |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/AuthenticateEntity <<EOF
{
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "password": "SecurePass123!",
  "ownership_proof_response": "123456",
  "client_publish_pub_key": "base64_x25519_publish_key",
  "client_device_id_pub_key": "base64_x25519_device_id_key"
}
EOF
```

---

### v1: List Entity Stored Tokens

Retrieves all stored tokens for an authenticated entity.

**Request:** `ListEntityStoredTokensRequest`

| Field             | Type | Required | Description                                  |
| ----------------- | ---- | -------- | -------------------------------------------- |
| long_lived_token  | string | Yes    | Session token from authentication            |
| migrate_to_device | bool | No       | Remove from cloud and send to device         |

**Response:** `ListEntityStoredTokensResponse`

| Field         | Type         | Description                     |
| ------------- | ------------ | ------------------------------- |
| stored_tokens | Token[]      | List of stored tokens           |
| message       | string       | Response message                |

**Token Object:**

| Field              | Type              | Description                         |
| ------------------ | ----------------- | ----------------------------------- |
| platform           | string            | Platform name (e.g., "gmail", "x")  |
| account_identifier | string            | Account identifier                  |
| account_tokens     | map<string, string> | Access, refresh, and ID tokens    |
| is_stored_on_device| bool              | Whether token is on device          |

**Example:**

```bash
grpcurl -plaintext -d '{"long_lived_token": "your_token"}' \
-proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/ListEntityStoredTokens
```

---

### v1: Delete An Entity

Deletes an entity from the vault.

> **Warning:** All stored tokens must be revoked before deletion.

**Request:** `DeleteEntityRequest`

| Field            | Type   | Required | Description          |
| ---------------- | ------ | -------- | -------------------- |
| long_lived_token | string | Yes      | Session token        |

**Response:** `DeleteEntityResponse`

| Field   | Type   | Description          |
| ------- | ------ | -------------------- |
| message | string | Response message     |
| success | bool   | Operation success    |

**Example:**

```bash
grpcurl -plaintext -d '{"long_lived_token": "your_token"}' \
-proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/DeleteEntity
```

---

### v1: Reset Password

Resets an entity's password with two-step verification.

#### Step 1: Initiate Reset

**Request:** `ResetPasswordRequest`

| Field                    | Type   | Required | Description                              |
| ------------------------ | ------ | -------- | ---------------------------------------- |
| phone_number             | string | Optional | Phone number in E164 format              |
| email_address            | string | Optional | Email address                            |
| new_password             | string | Yes      | New secure password                      |
| captcha_token            | string | Yes*     | Captcha verification token (*if captcha enabled)|
| client_publish_pub_key   | string | Yes      | X25519 public key for publishing (base64)|
| client_device_id_pub_key | string | Yes      | X25519 public key for device ID (base64) |

**Response:** `ResetPasswordResponse`

| Field                    | Type   | Description                        |
| ------------------------ | ------ | ---------------------------------- |
| requires_ownership_proof | bool   | Whether ownership proof is required|
| next_attempt_timestamp   | int32  | Next available OTP request time    |
| message                  | string | Response message                   |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/ResetPassword <<EOF
{
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "new_password": "NewSecurePass123!",
  "captcha_token": "captcha_token_value",
  "client_publish_pub_key": "base64_x25519_publish_key",
  "client_device_id_pub_key": "base64_x25519_device_id_key"
}
EOF
```

#### Step 2: Complete Reset

**Request:** `ResetPasswordRequest`

| Field                    | Type   | Required | Description                              |
| ------------------------ | ------ | -------- | ---------------------------------------- |
| phone_number             | string | Optional | Phone number in E164 format              |
| email_address            | string | Optional | Email address                            |
| new_password             | string | Yes      | New secure password                      |
| ownership_proof_response | string | Yes      | OTP code from step 1                     |
| client_publish_pub_key   | string | Yes      | X25519 public key for publishing (base64)|
| client_device_id_pub_key | string | Yes      | X25519 public key for device ID (base64) |

**Response:** `ResetPasswordResponse`

| Field                    | Type   | Description                          |
| ------------------------ | ------ | ------------------------------------ |
| long_lived_token         | string | Session token                        |
| server_publish_pub_key   | string | Server X25519 publish key (base64)   |
| server_device_id_pub_key | string | Server X25519 device ID key (base64) |
| message                  | string | Response message                     |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/ResetPassword <<EOF
{
  "phone_number": "+237123456789",
  "email_address": "user@example.com",
  "new_password": "NewSecurePass123!",
  "ownership_proof_response": "123456",
  "client_publish_pub_key": "base64_x25519_publish_key",
  "client_device_id_pub_key": "base64_x25519_device_id_key"
}
EOF
```

---

### v1: Update Password

Updates an entity's password (requires current password).

**Request:** `UpdateEntityPasswordRequest`

| Field            | Type   | Required | Description          |
| ---------------- | ------ | -------- | -------------------- |
| long_lived_token | string | Yes      | Session token        |
| current_password | string | Yes      | Current password     |
| new_password     | string | Yes      | New secure password  |

**Response:** `UpdateEntityPasswordResponse`

| Field   | Type   | Description       |
| ------- | ------ | ----------------- |
| message | string | Response message  |
| success | bool   | Operation success |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.Entity/UpdateEntityPassword <<EOF
{
  "long_lived_token": "your_token",
  "current_password": "CurrentPass123!",
  "new_password": "NewPass123!"
}
EOF
```

---

## v1 Internal Service

Service for internal backend operations.

### v1: Store Token

Stores an OAuth2 token for an entity.

**Request:** `StoreEntityTokenRequest`

| Field              | Type   | Required | Description                |
| ------------------ | ------ | -------- | -------------------------- |
| long_lived_token   | string | Yes      | Session token              |
| token              | string | Yes      | OAuth2 token (JSON string) |
| platform           | string | Yes      | Platform name              |
| account_identifier | string | Yes      | Account identifier         |

**Response:** `StoreEntityTokenResponse`

| Field   | Type   | Description       |
| ------- | ------ | ----------------- |
| message | string | Response message  |
| success | bool   | Operation success |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/StoreEntityToken <<EOF
{
  "long_lived_token": "your_token",
  "token": "{\"access_token\":\"...\"}",
  "platform": "gmail",
  "account_identifier": "user@gmail.com"
}
EOF
```

---

### v1: Get Access Token

Retrieves an entity's access token for a specific platform.

**Request:** `GetEntityAccessTokenRequest`

| Field              | Type   | Required | Description                        |
| ------------------ | ------ | -------- | ---------------------------------- |
| device_id          | string | Optional | Device identifier                  |
| phone_number       | string | Optional | Phone number                       |
| long_lived_token   | string | Optional | Session token                      |
| platform           | string | Yes      | Platform name                      |
| account_identifier | string | Yes      | Account identifier                 |

**Response:** `GetEntityAccessTokenResponse`

| Field   | Type   | Description              |
| ------- | ------ | ------------------------ |
| token   | string | Access token (JSON)      |
| message | string | Response message         |
| success | bool   | Operation success        |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/GetEntityAccessToken <<EOF
{
  "device_id": "device_123",
  "platform": "gmail",
  "account_identifier": "user@gmail.com"
}
EOF
```

---

### v1: Decrypt Payload

Decrypts an encrypted payload.

**Request:** `DecryptPayloadRequest`

| Field              | Type   | Required | Description          |
| ------------------ | ------ | -------- | -------------------- |
| device_id          | string | Optional | Device identifier    |
| phone_number       | string | Optional | Phone number         |
| payload_ciphertext | string | Yes      | Encrypted payload    |

**Response:** `DecryptPayloadResponse`

| Field             | Type   | Description           |
| ----------------- | ------ | --------------------- |
| payload_plaintext | string | Decrypted payload     |
| message           | string | Response message      |
| success           | bool   | Operation success     |
| country_code      | string | Entity's country code |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/DecryptPayload <<EOF
{
  "device_id": "device_123",
  "payload_ciphertext": "encrypted_data"
}
EOF
```

---

### v1: Encrypt Payload

Encrypts a plaintext payload.

**Request:** `EncryptPayloadRequest`

| Field             | Type   | Required | Description       |
| ----------------- | ------ | -------- | ----------------- |
| device_id         | string | Optional | Device identifier |
| phone_number      | string | Optional | Phone number      |
| payload_plaintext | string | Yes      | Plaintext payload |

**Response:** `EncryptPayloadResponse`

| Field              | Type   | Description        |
| ------------------ | ------ | ------------------ |
| payload_ciphertext | string | Encrypted payload  |
| message            | string | Response message   |
| success            | bool   | Operation success  |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/EncryptPayload <<EOF
{
  "device_id": "device_123",
  "payload_plaintext": "plaintext_data"
}
EOF
```

---

### v1: Update Token

Updates an entity's stored token.

**Request:** `UpdateEntityTokenRequest`

| Field              | Type   | Required | Description                |
| ------------------ | ------ | -------- | -------------------------- |
| device_id          | string | Optional | Device identifier          |
| phone_number       | string | Optional | Phone number               |
| token              | string | Yes      | New token (JSON string)    |
| platform           | string | Yes      | Platform name              |
| account_identifier | string | Yes      | Account identifier         |

**Response:** `UpdateEntityTokenResponse`

| Field   | Type   | Description       |
| ------- | ------ | ----------------- |
| message | string | Response message  |
| success | bool   | Operation success |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/UpdateEntityToken <<EOF
{
  "device_id": "device_123",
  "token": "{\"access_token\":\"new_token\"}",
  "platform": "gmail",
  "account_identifier": "user@gmail.com"
}
EOF
```

---

### v1: Delete Token

Deletes an entity's stored token.

**Request:** `DeleteEntityTokenRequest`

| Field              | Type   | Required | Description        |
| ------------------ | ------ | -------- | ------------------ |
| long_lived_token   | string | Yes      | Session token      |
| platform           | string | Yes      | Platform name      |
| account_identifier | string | Yes      | Account identifier |

**Response:** `DeleteEntityTokenResponse`

| Field   | Type   | Description       |
| ------- | ------ | ----------------- |
| message | string | Response message  |
| success | bool   | Operation success |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/DeleteEntityToken <<EOF
{
  "long_lived_token": "your_token",
  "platform": "gmail",
  "account_identifier": "user@gmail.com"
}
EOF
```

---

### v1: Create Bridge Entity

Creates a bridge entity with two-step verification.

#### Step 1: Initiate Bridge Creation

**Request:** `CreateBridgeEntityRequest`

| Field                  | Type   | Required | Description                         |
| ---------------------- | ------ | -------- | ----------------------------------- |
| country_code           | string | Yes      | ISO 3166-1 alpha-2 code             |
| phone_number           | string | Yes      | Phone number in E164 format         |
| client_publish_pub_key | string | Yes      | X25519 publish key (base64)         |
| language               | string | No       | Preferred language (ISO 639-1)      |

**Response:** `CreateBridgeEntityResponse`

| Field   | Type   | Description       |
| ------- | ------ | ----------------- |
| message | string | Response message  |
| success | bool   | Operation success |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/CreateBridgeEntity <<EOF
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "client_publish_pub_key": "base64_x25519_key",
  "language": "en"
}
EOF
```

#### Step 2: Complete Bridge Creation

**Request:** `CreateBridgeEntityRequest`

| Field                    | Type   | Required | Description                    |
| ------------------------ | ------ | -------- | ------------------------------ |
| country_code             | string | Yes      | ISO 3166-1 alpha-2 code        |
| phone_number             | string | Yes      | Phone number in E164 format    |
| ownership_proof_response | string | Yes      | OTP code from step 1           |

**Response:** `CreateBridgeEntityResponse`

| Field   | Type   | Description       |
| ------- | ------ | ----------------- |
| message | string | Response message  |
| success | bool   | Operation success |

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/CreateBridgeEntity <<EOF
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "ownership_proof_response": "123456"
}
EOF
```

---

### v1: Authenticate Bridge Entity

Authenticates a bridge entity.

**Request:** `AuthenticateBridgeEntityRequest`

| Field        | Type   | Required | Description                    |
| ------------ | ------ | -------- | ------------------------------ |
| phone_number | string | Yes      | Phone number in E164 format    |
| language     | string | No       | Preferred language (ISO 639-1) |

**Response:** `AuthenticateBridgeEntityResponse`

| Field    | Type   | Description                |
| -------- | ------ | -------------------------- |
| message  | string | Response message           |
| success  | bool   | Operation success          |
| language | string | Entity's preferred language|

**Example:**

```bash
grpcurl -plaintext -d @ -proto protos/v1/vault.proto \
<your_host>:<your_port> vault.v1.EntityInternal/AuthenticateBridgeEntity <<EOF
{
  "phone_number": "+237123456789",
  "language": "en"
}
EOF
```

---

> [!NOTE]
>
>All gRPC responses return standard status codes. `0 OK` indicates success. See [gRPC Status Codes](https://grpc.github.io/grpc/core/md_doc_statuscodes.html) for error codes.
