# Vault gRPC Documentation

## Table of Contents

- [Download Protocol Buffer File](#download-protocol-buffer-file)
  - [Version 1](#version-1)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Public Functions](#public-functions)
    - [Create an Entity](#create-an-entity)
      - [Initiate Creation](#initiate-creation)
      - [Complete Creation](#complete-creation)
    - [Authenticate an Entity](#authenticate-an-entity)
      - [Initiate Authentication](#initiate-authentication)
      - [Complete Authentication](#complete-authentication)
    - [List an Entity's Stored Tokens](#list-an-entitys-stored-tokens)
    - [Delete An Entity](#delete-an-entity)
    - [Reset an Entity's Password](#reset-an-entitys-password)
      - [Initiate Reset](#initiate-reset)
      - [Complete Reset](#complete-reset)
    - [Update an entity's Password](#update-an-entitys-password)
  - [Internal Functions](#internal-functions)
    - [Store an Entity's Token](#store-an-entitys-token)
    - [Get Entity Access Token](#get-entity-access-token)
    - [Decrypt Payload](#decrypt-payload)
    - [Encrypt Payload](#encrypt-payload)
    - [Update An Entity Token](#update-an-entitys-token)
    - [Delete An Entity's Token](#delete-an-entitys-token)
    - [Create Bridge Entity](#create-bridge-entity)
      - [Initiate Bridge Creation](#initiate-bridge-creation)
      - [Complete Bridge Creation](#complete-bride-creation)
    - [Authenticate Bridge Entity](#authenticate-bridge-entity)

## Download Protocol Buffer File

To use the gRPC functions, download the protocol buffer file from the
[proto](/protos/) directory corresponding to the desired version.

### Version 1

```bash
curl -O -L https://raw.githubusercontent.com/smswithoutborders/SMSwithoutborders-BE/feature/grpc_api/protos/v1/vault.proto
```

## Prerequisites

### Install Dependencies

If you're using Python, install the necessary dependencies from
`requirements.txt`. For other languages, see
[Supported languages](https://grpc.io/docs/languages/).

> [!TIP]
>
> it's recommended to set up a virtual environment to isolate your project's
> dependencies.

```bash
python3 -m venv venv
source venv/bin/activate
```

```bash
pip install -r requirements.txt
```

### Compile gRPC for Python

If you're using Python, compile the gRPC files with `protoc` to generate the
necessary Python files. For other languages, see
[Supported languages](https://grpc.io/docs/languages/).

```bash
python -m grpc_tools.protoc -I protos/v1 --python_out=. --grpc_python_out=. protos/v1/vault.proto
```

### Starting the Server

#### Quick Start (for Development Only):

#### Public Server

```bash
HASHING_SALT=/path/to/hashing.key \
SHARED_KEY=/path/to/shared.key \
KEYSTORE_PATH=/path/to/key_store \
SQLITE_DATABASE_PATH=/path/to/local.db \
GRPC_PORT=6000 \
HOST=127.0.0.1 \
python3 grpc_server.py
```

#### Internal Server

```bash
HASHING_SALT=/path/to/hashing.key \
SHARED_KEY=/path/to/shared.key \
KEYSTORE_PATH=/path/to/key_store \
SQLITE_DATABASE_PATH=/path/to/local.db \
GRPC_INTERNAL_PORT=6099 \
HOST=127.0.0.1 \
python3 grpc_internal_server.py
```

## Usage

## Public Functions

These functions are exposed to external clients for interaction with the vault.

---

### Create an Entity

An entity represents a user or client in the vault.

---

#### Initiate Creation

Before creating an entity, you must prove ownership of the phone number you
intend to use. This step ensures the security and authenticity of the entity
creation process.

---

##### Request

> `request` **CreateEntityRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                    | Type   | Description                                                                                                                                |
| ------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| phone_number             | string | The phone number associated with the entity. It should be in [E164 format](https://en.wikipedia.org/wiki/E.164). e.g., +237123456789.      |
| country_code             | string | The [ISO 3166-1 alpha-2 code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) associated with the phone number. e.g., `CM` for Cameroon. |
| password                 | string | A secure password for the entity.                                                                                                          |
| client_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                                                                                   |
| client_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                                                                                    |
| captcha_id               | string | The captcha identifier (optional, used when captcha verification is required).                                                             |
| captcha_answer           | string | The user's answer to the captcha (optional, used when completing a captcha challenge).                                                     |

---

##### Response

> `response` **CreateEntityResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field                    | Type   | Description                                                                                                 |
| ------------------------ | ------ | ----------------------------------------------------------------------------------------------------------- |
| requires_ownership_proof | bool   | An indicator if proof of ownership is required. `true` if required, `false` otherwise.                      |
| next_attempt_timestamp   | int32  | The next available time to request another proof of ownership (in Unix seconds) if the first attempt fails. |
| message                  | string | A response message from the server.                                                                         |
| requires_captcha         | bool   | An indicator if captcha verification is required before proceeding. `true` if required, `false` otherwise.  |
| captcha_id               | string | The captcha identifier (returned when captcha verification is required).                                    |
| captcha_image            | string | Base64-encoded captcha image (returned when captcha verification is required).                              |

---

##### Method

> `method` **CreateEntity**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/CreateEntity <payload.json
```

---

**Sample payload.json**

```json
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "password": "Password@123",
  "client_publish_pub_key": "x25519 client publish public key",
  "client_device_id_pub_key": "x25519 client device_id public key"
}
```

---

**Sample response**

```json
{
  "requiresOwnershipProof": true,
  "message": "OTP sent successfully. Check your phone for the code.",
  "nextAttemptTimestamp": 1717323582
}
```

**Sample response (when captcha is required)**

```json
{
  "requiresCaptcha": true,
  "message": "Solve the captcha to proceed.",
  "captchaId": "captcha_id_123",
  "captchaImage": "base64_encoded_captcha_image"
}
```

---

#### Complete Creation

> [!WARNING]
>
> Ensure that you have completed the [Initiate Creation](#initiate-creation)
> step before executing this step.

---

##### Request

> `request` **CreateEntityRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                    | Type   | Description                                                                                                                                |
| ------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| phone_number             | string | The phone number associated with the entity. It should be in [E164 format](https://en.wikipedia.org/wiki/E.164). e.g., +237123456789.      |
| country_code             | string | The [ISO 3166-1 alpha-2 code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) associated with the phone number. e.g., `CM` for Cameroon. |
| password                 | string | A secure password for the entity.                                                                                                          |
| ownership_proof_response | string | The proof response from the previous step.                                                                                                 |
| client_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                                                                                   |
| client_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                                                                                    |

---

##### Response

> `response` **CreateEntityResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field                    | Type   | Description                                                                |
| ------------------------ | ------ | -------------------------------------------------------------------------- |
| message                  | string | A response message from the server.                                        |
| server_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                   |
| server_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                    |
| long_lived_token         | string | A token for the authenticated session, to be used for subsequent requests. |

---

##### Method

> `method` **CreateEntity**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/CreateEntity <payload.json
```

---

**Sample payload.json**

```json
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "password": "Password@123",
  "client_publish_pub_key": "x25519 client publish public key",
  "client_device_id_pub_key": "x25519 client device_id public key",
  "ownership_proof_response": "123456"
}
```

---

**Sample response**

```json
{
  "longLivedToken": "long_lived_token",
  "serverPublishPubKey": "x25519 server publish public key",
  "serverDeviceIdPubKey": "x25519 server publish public key",
  "message": "Entity created successfully"
}
```

---

### Authenticate an Entity

An entity represents a user or client in the vault.

> [!WARNING]
>
> Repeated incorrect password attempts will trigger a dynamic rate limit and
> return an `UNAVAILABLE` status code for this function.

#### Initiate Authentication

This step involves verifying the phone number and password, triggering a proof
of ownership for the phone number.

---

##### Request

> `request` **AuthenticateEntityRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                    | Type   | Description                                                                                                                           |
| ------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| phone_number             | string | The phone number associated with the entity. It should be in [E164 format](https://en.wikipedia.org/wiki/E.164). e.g., +237123456789. |
| password                 | string | A secure password for the entity.                                                                                                     |
| client_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                                                                              |
| client_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                                                                               |
| captcha_id               | string | The captcha identifier (optional, used when captcha verification is required).                                                        |
| captcha_answer           | string | The user's answer to the captcha (optional, used when completing a captcha challenge).                                                |

---

##### Response

> `response` **AuthenticateEntityResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field                    | Type   | Description                                                                                                 |
| ------------------------ | ------ | ----------------------------------------------------------------------------------------------------------- |
| requires_ownership_proof | bool   | An indicator if proof of ownership is required. `true` if required, `false` otherwise.                      |
| requires_password_reset  | bool   | An indicator if a user must reset their password. `true` if required, `false` otherwise.                    |
| next_attempt_timestamp   | int32  | The next available time to request another proof of ownership (in Unix seconds) if the first attempt fails. |
| message                  | string | A response message from the server.                                                                         |
| requires_captcha         | bool   | An indicator if captcha verification is required before proceeding. `true` if required, `false` otherwise.  |
| captcha_id               | string | The captcha identifier (returned when captcha verification is required).                                    |
| captcha_image            | string | Base64-encoded captcha image (returned when captcha verification is required).                              |

---

##### Method

> `method` **AuthenticateEntity**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/AuthenticateEntity <payload.json
```

---

**Sample payload.json**

```json
{
  "phone_number": "+237123456789",
  "password": "Password@123",
  "client_publish_pub_key": "x25519 client publish public key",
  "client_device_id_pub_key": "x25519 client device_id public key"
}
```

---

**Sample response**

```json
{
  "requiresOwnershipProof": true,
  "message": "OTP sent successfully. Check your phone for the code.",
  "nextAttemptTimestamp": 1717323582
}
```

**Sample response (when captcha is required)**

```json
{
  "requiresCaptcha": true,
  "message": "Solve the captcha to proceed.",
  "captchaId": "captcha_id_123",
  "captchaImage": "base64_encoded_captcha_image"
}
```

---

#### Complete Authentication

> [!WARNING]
>
> Ensure that you have completed the
> [Initiate Authentication](#initiate-authentication) step before executing this
> step.

---

##### Request

> `request` **AuthenticateEntityRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                    | Type   | Description                                                                                                                           |
| ------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| phone_number             | string | The phone number associated with the entity. It should be in [E164 format](https://en.wikipedia.org/wiki/E.164). e.g., +237123456789. |
| password                 | string | A secure password for the entity.                                                                                                     |
| ownership_proof_response | string | The proof response from the previous step.                                                                                            |
| client_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                                                                              |
| client_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                                                                               |

---

##### Response

> `response` **AuthenticateEntityResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field                    | Type   | Description                                                                |
| ------------------------ | ------ | -------------------------------------------------------------------------- |
| message                  | string | A response message from the server.                                        |
| server_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                   |
| server_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                    |
| long_lived_token         | string | A token for the authenticated session, to be used for subsequent requests. |

---

##### Method

> `method` **AuthenticateEntity**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/AuthenticateEntity <payload.json
```

---

**Sample payload.json**

```json
{
  "phone_number": "+237123456789",
  "password": "Password@123",
  "client_publish_pub_key": "x25519 client publish public key",
  "client_device_id_pub_key": "x25519 client device_id public key",
  "ownership_proof_response": "123456"
}
```

---

**Sample response**

```json
{
  "longLivedToken": "long_lived_token",
  "serverPublishPubKey": "x25519 server publish public key",
  "serverDeviceIdPubKey": "x25519 server publish public key",
  "message": "Entity authenticated successfully!"
}
```

### Create Bridge Entity

An entity represents a user or client in the vault.

---

#### Initiate Bridge Creation

Before creating a bridge entity, you must prove ownership of the phone number you
intend to use. This step ensures security and authenticity in the entity creation process.

---

##### Request

> `request` **CreateBridgeEntityRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                  | Type   | Description                                                                                                                                  |
| ---------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| phone_number           | string | The phone number associated with the bridge entity. It should be in [E164 format](https://en.wikipedia.org/wiki/E.164), e.g., +237123456789. |
| country_code           | string | The [ISO 3166-1 alpha-2 code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) associated with the phone number. e.g., `CM` for Cameroon.   |
| client_publish_pub_key | string | An `X25519` public key for publishing, `base64 encoded`.                                                                                     |

---

##### Response

> `response` **CreateBridgeEntityResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type   | Description                                                        |
| ------- | ------ | ------------------------------------------------------------------ |
| message | string | A response message from the server.                                |
| success | bool   | Indicates whether the operation was successful. `true` or `false`. |

---

##### Method

> `method` **CreateBridgeEntity**

> [!TIP]
>
> The examples below use [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/CreateBridgeEntity <payload.json
```

---

**Sample payload.json**

```json
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "client_publish_pub_key": "x25519 client publish public key"
}
```

---

**Sample response**

```json
{
  "success": true,
  "message": "Bridge entity created successfully."
}
```

---

#### Complete Bridge Creation

> [!WARNING]
>
> Ensure that you have completed the [Initiate Bridge Creation](#initiate-bridge-creation)
> step before executing this step.

---

##### Request

> `request` **CreateBridgeEntityRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                    | Type   | Description                                                                                                                                  |
| ------------------------ | ------ | -------------------------------------------------------------------------------------------------------------------------------------------- |
| phone_number             | string | The phone number associated with the bridge entity. It should be in [E164 format](https://en.wikipedia.org/wiki/E.164). e.g., +237123456789. |
| country_code             | string | The [ISO 3166-1 alpha-2 code](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) associated with the phone number. e.g., `CM` for Cameroon.   |
| ownership_proof_response | string | The proof response from the previous step.                                                                                                   |

---

##### Response

> `response` **CreateBridgeEntityResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type   | Description                                                        |
| ------- | ------ | ------------------------------------------------------------------ |
| message | string | A response message from the server.                                |
| success | bool   | Indicates whether the operation was successful. `true` or `false`. |

---

##### Method

> `method` **CreateBridgeEntity**

> [!TIP]
>
> The examples below use [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/CreateBridgeEntity <payload.json
```

---

**Sample payload.json**

```json
{
  "country_code": "CM",
  "phone_number": "+237123456789",
  "ownership_proof_response": "123456"
}
```

---

**Sample response**

```json
{
  "success": true,
  "message": "Bridge entity creation completed successfully."
}
```

---

### Authenticate Bridge Entity

An entity represents a user or client in the vault.

---

##### Request

> `request` **AuthenticateBridgeEntityRequest**

| Field        | Type   | Description                                         |
| ------------ | ------ | --------------------------------------------------- |
| phone_number | string | The phone number associated with the bridge entity. |

---

##### Response

> `response` **AuthenticateBridgeEntityResponse**

| Field   | Type   | Description                                      |
| ------- | ------ | ------------------------------------------------ |
| message | string | A response message from the server.              |
| success | bool   | Indicates whether authentication was successful. |

---

##### Method

> `method` **AuthenticateBridgeEntity**

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/AuthenticateBridgeEntity <payload.json
```

---

**Sample payload.json**

```json
{
  "phone_number": "+237123456789"
}
```

---

**Sample response**

```json
{
  "success": true,
  "message": "Bridge entity authenticated successfully."
}
```

### List an Entity's Stored Tokens

This method retrieves the stored tokens for a given entity.

---

##### Request

> `request` **ListEntityStoredTokensRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field            | Type   | Description                                                                      |
| ---------------- | ------ | -------------------------------------------------------------------------------- |
| long_lived_token | string | The long-lived token for the authenticated session, used to identify the entity. |

Optional fields:

| Field             | Type | Description                                                                     |
| ----------------- | ---- | ------------------------------------------------------------------------------- |
| migrate_to_device | bool | Indicates if the token should be removed from the cloud and sent to the device. |

---

##### Response

> `response` **ListEntityStoredTokensResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field         | Type   | Description                                                                                                           |
| ------------- | ------ | --------------------------------------------------------------------------------------------------------------------- |
| stored_tokens | array  | A list of stored tokens. Each token object may contain various fields. See [Token Object](#token-object) for details. |
| message       | string | A response message from the server.                                                                                   |

##### Token Object

> `message` **Token**

| Field               | Type                | Description                                                                                             |
| ------------------- | ------------------- | ------------------------------------------------------------------------------------------------------- |
| platform            | string              | The platform associated with the token.                                                                 |
| account_identifier  | string              | The unique identifier of the account associated with the token.                                         |
| account_tokens      | map<string, string> | Contains the access, refresh, and ID tokens with keys: `access_token`, `refresh_token`, and `id_token`. |
| is_stored_on_device | bool                | Indicates if the token is already stored on the device.                                                 |

---

##### Method

> `method` **ListEntityStoredTokens**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d '{"long_lived_token": "long_lived_token"}' \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/ListEntityStoredTokens
```

---

**Sample response**

```json
{
  "stored_tokens": [
    {
      "account_identifier": "my_x_handle",
      "platform": "x"
    },
    {
      "account_identifier": "example@gmail.com",
      "platform": "gmail"
    }
  ],
  "message": "Tokens retrieved successfully."
}
```

---

### Delete An Entity

This function deletes an entity.

> [!WARNING]
>
> Ensure all stored tokens associated with this entity have been revoked before
> using this function. Failure to do so will result in a `FAILED_PRECONDITION`
> error.

---

##### Request

> `request` **DeleteEntityRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field            | Type   | Description                                         |
| ---------------- | ------ | --------------------------------------------------- |
| long_lived_token | string | The long-lived token for the authenticated session. |

---

##### Response

> `response` **DeleteEntityResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type   | Description                                |
| ------- | ------ | ------------------------------------------ |
| message | string | A response message from the server.        |
| success | bool   | Indicates if the operation was successful. |

---

##### Method

> `method` **DeleteEntity**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d '{"long_lived_token": "long_lived_token"}' \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/DeleteEntity
```

---

**Sample response**

```json
{
  "message": "Entity deleted successfully.",
  "success": true
}
```

---

### Reset an Entity's Password

In case of forgotten passwords, they can be reset with the following steps.

#### Initiate Reset

This step involves verifying the phone number, triggering a proof
of ownership for the phone number.

---

##### Request

> `request` **ResetPasswordRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                    | Type   | Description                                                                                                                           |
| ------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| phone_number             | string | The phone number associated with the entity. It should be in [E164 format](https://en.wikipedia.org/wiki/E.164). e.g., +237123456789. |
| new_password             | string | A new secure password for the entity.                                                                                                 |
| client_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                                                                              |
| client_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                                                                               |
| captcha_id               | string | The captcha identifier (optional, used when captcha verification is required).                                                        |
| captcha_answer           | string | The user's answer to the captcha (optional, used when completing a captcha challenge).                                                |

---

##### Response

> `response` **ResetPasswordResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field                    | Type   | Description                                                                                                 |
| ------------------------ | ------ | ----------------------------------------------------------------------------------------------------------- |
| requires_ownership_proof | bool   | An indicator if proof of ownership is required. `true` if required, `false` otherwise.                      |
| next_attempt_timestamp   | int32  | The next available time to request another proof of ownership (in Unix seconds) if the first attempt fails. |
| message                  | string | A response message from the server.                                                                         |
| requires_captcha         | bool   | An indicator if captcha verification is required before proceeding. `true` if required, `false` otherwise.  |
| captcha_id               | string | The captcha identifier (returned when captcha verification is required).                                    |
| captcha_image            | string | Base64-encoded captcha image (returned when captcha verification is required).                              |

---

##### Method

> `method` **ResetPassword**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/ResetPassword <payload.json
```

---

**Sample payload.json**

```json
{
  "phone_number": "+237123456789",
  "new_password": "Password@123",
  "client_publish_pub_key": "x25519 client publish public key",
  "client_device_id_pub_key": "x25519 client device_id public key"
}
```

---

**Sample response**

```json
{
  "requiresOwnershipProof": true,
  "message": "OTP sent successfully. Check your phone for the code.",
  "nextAttemptTimestamp": 1717323582
}
```

**Sample response (when captcha is required)**

```json
{
  "requiresCaptcha": true,
  "message": "Solve the captcha to proceed.",
  "captchaId": "captcha_id_123",
  "captchaImage": "base64_encoded_captcha_image"
}
```

---

#### Complete Reset

> [!WARNING]
>
> Ensure that you have completed the
> [Initiate Reset](#initiate-reset) step before executing this
> step.

---

##### Request

> `request` **ResetPasswordRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                    | Type   | Description                                                                                                                           |
| ------------------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| phone_number             | string | The phone number associated with the entity. It should be in [E164 format](https://en.wikipedia.org/wiki/E.164). e.g., +237123456789. |
| new_password             | string | A new secure password for the entity.                                                                                                 |
| ownership_proof_response | string | The proof response from the previous step.                                                                                            |
| client_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                                                                              |
| client_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                                                                               |

---

##### Response

> `response` **ResetPasswordResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field                    | Type   | Description                                                                |
| ------------------------ | ------ | -------------------------------------------------------------------------- |
| message                  | string | A response message from the server.                                        |
| server_publish_pub_key   | string | An `X25519` public key for publishing, `base64 encoded`.                   |
| server_device_id_pub_key | string | An `X25519` public key for device ID, `base64 encoded`.                    |
| long_lived_token         | string | A token for the authenticated session, to be used for subsequent requests. |

---

##### Method

> `method` **ResetPassword**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/ResetPassword <payload.json
```

---

**Sample payload.json**

```json
{
  "phone_number": "+237123456789",
  "new_password": "Password@123",
  "client_publish_pub_key": "x25519 client publish public key",
  "client_device_id_pub_key": "x25519 client device_id public key",
  "ownership_proof_response": "123456"
}
```

---

**Sample response**

```json
{
  "longLivedToken": "long_lived_token",
  "serverPublishPubKey": "x25519 server publish public key",
  "serverDeviceIdPubKey": "x25519 server publish public key",
  "message": "Password reset successfully!"
}
```

---

### Update an entity's Password

This method updates the password for a given entity.

> [!WARNING]
>
> Repeated incorrect password attempts will trigger a dynamic rate limit and
> return an `UNAVAILABLE` status code for this function.

---

##### Request

> `request` **UpdateEntityPasswordRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field            | Type   | Description                                                                      |
| ---------------- | ------ | -------------------------------------------------------------------------------- |
| long_lived_token | string | The long-lived token for the authenticated session, used to identify the entity. |
| current_password | string | The current password of the entity.                                              |
| new_password     | string | The new password of the entity.                                                  |

---

##### Response

> `response` **UpdateEntityPasswordResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type   | Description                                |
| ------- | ------ | ------------------------------------------ |
| message | string | A response message from the server.        |
| success | bool   | Indicates if the operation was successful. |

---

##### Method

> `method` **UpdateEntityPassword**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/UpdateEntityPassword <payload.json
```

---

**Sample payload.json**

```json
{
  "current_password": "current_password",
  "long_lived_token": "long_lived_token",
  "new_password": "new_password."
}
```

---

**Sample response**

```json
{
  "message": "Password updated successfully.",
  "success": true
}
```

---

## Internal Functions

These functions handle internal operations and are not directly exposed to
external clients.

---

### Store an Entity's Token

This step involves storing tokens securely for the authenticated entity.

---

##### Request

> `request` **StoreEntityTokenRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field              | Type   | Description                                                         |
| ------------------ | ------ | ------------------------------------------------------------------- |
| long_lived_token   | string | The long-lived token for the authenticated session.                 |
| token              | string | The token to be stored.                                             |
| platform           | string | The platform from which the token is being issued. (e.g., "gmail"). |
| account_identifier | string | The identifier of the account associated with the token.            |

Optional fields:

| Field         | Type   | Description                                          |
| ------------- | ------ | ---------------------------------------------------- |
| code_verifier | string | A cryptographic random string used in the PKCE flow. |

---

##### Response

> `response` **StoreEntityTokenResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type    | Description                                |
| ------- | ------- | ------------------------------------------ |
| message | string  | A response message from the server.        |
| success | boolean | Indicates if the operation was successful. |

---

##### Method

> `method` **StoreEntityToken**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/StoreEntityToken <payload.json
```

---

**Sample payload.json**

```json
{
  "long_lived_token": "long_lived_token",
  "authorization_code": "oauth2_code",
  "platform": "gmail",
  "protocol": "oauth2"
}
```

---

**Sample response**

```json
{
  "message": "Token stored successfully.",
  "success": true
}
```

### Get Entity Access Token

This function retrieves an entity's access token.

---

##### Request

> `request` **GetEntityAccessTokenRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                                         | Type   | Description                                                                                         |
| --------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------- |
| device_id or phone_number or long_lived_token | string | The unique identifier of the device or the phone number or the long lived token used by the entity. |
| platform                                      | string | The platform from which the token is being issued. (e.g., "gmail").                                 |
| account_identifier                            | string | The identifier of the account associated with the token.                                            |

---

##### Response

> `response` **GetEntityAccessTokenResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type   | Description                                                                |
| ------- | ------ | -------------------------------------------------------------------------- |
| message | string | A response message from the server.                                        |
| success | bool   | Indicates if the operation was successful.                                 |
| token   | string | The retrieved token associated with the entity for the specified platform. |

---

##### Method

> `method` **GetEntityAccessToken**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d '{"device_id": "device_id", "platform": "gmail", "account_identifier": "sample@mail.com"}' \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/GetEntityAccessToken
```

---

**Sample response**

```json
{
  "message": "Successfully fetched tokens",
  "success": true,
  "token": "retrieved_token"
}
```

---

### Decrypt Payload

This function handles decrypting payload content.

---

##### Request

> `request` **DecryptPayloadRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                     | Type   | Description                                                                 |
| ------------------------- | ------ | --------------------------------------------------------------------------- |
| device_id or phone_number | string | The unique identifier of the device or the phone number used by the entity. |
| payload_ciphertext        | string | The encrypted payload ciphertext that needs to be decrypted.                |

---

##### Response

> `response` **DecryptPayloadResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field             | Type   | Description                                |
| ----------------- | ------ | ------------------------------------------ |
| message           | string | A response message from the server.        |
| success           | bool   | Indicates if the operation was successful. |
| payload_plaintext | string | The decrypted payload plaintext.           |

---

##### Method

> `method` **DecryptPayload**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d '{"device_id": "device_id", "payload_ciphertext": "encrypted_payload"}' \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/DecryptPayload
```

---

**Sample response**

```json
{
  "message": "Successfully decrypted payload",
  "success": true,
  "payload_plaintext": "Decrypted payload content"
}
```

---

### Encrypt Payload

This function handles the encryption of payload content.

---

##### Request

> `request` **EncryptPayloadRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field             | Type   | Description                                             |
| ----------------- | ------ | ------------------------------------------------------- |
| device_id         | string | The unique identifier of the device used by the entity. |
| payload_plaintext | string | The plaintext payload content to be encrypted.          |

---

##### Response

> `response` **EncryptPayloadResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field              | Type   | Description                                |
| ------------------ | ------ | ------------------------------------------ |
| message            | string | A response message from the server.        |
| payload_ciphertext | string | The encrypted payload ciphertext.          |
| success            | bool   | Indicates if the operation was successful. |

---

##### Method

> `method` **EncryptPayload**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d '{"device_id": "device_id", "payload_plaintext": "plaintext_payload"}' \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/EncryptPayload
```

---

**Sample response**

```json
{
  "message": "Successfully encrypted payload.",
  "payload_ciphertext": "encrypted_payload",
  "success": true
}
```

---

### Update An Entity's Token

This function updates tokens associated with an entity.

---

##### Request

> `request` **UpdateEntityTokenRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field                     | Type   | Description                                                                 |
| ------------------------- | ------ | --------------------------------------------------------------------------- |
| device_id or phone_number | string | The unique identifier of the device or the phone number used by the entity. |
| token                     | string | The new token to be updated for the entity.                                 |
| platform                  | string | The platform from which the token is being updated. (e.g., "gmail").        |
| account_identifier        | string | The identifier of the account associated with the token.                    |

---

##### Response

> `response` **UpdateEntityTokenResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type   | Description                                |
| ------- | ------ | ------------------------------------------ |
| message | string | A response message from the server.        |
| success | bool   | Indicates if the operation was successful. |

---

##### Method

> `method` **UpdateEntityToken**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d '{"device_id": "device_id", "token": "new_token", "platform": "gmail", "account_identifier": "sample@mail.com"}' \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/UpdateEntityToken
```

---

**Sample response**

```json
{
  "message": "Token updated successfully.",
  "success": true
}
```

---

### Delete An Entity's Token

This function deletes tokens associated with an entity.

---

##### Request

> `request` **DeleteEntityTokenRequest**

> [!IMPORTANT]
>
> The table lists only the required fields for this step. Other fields will be
> ignored.

| Field              | Type   | Description                                                          |
| ------------------ | ------ | -------------------------------------------------------------------- |
| long_lived_token   | string | The long-lived token for the authenticated session.                  |
| platform           | string | The platform from which the token is being updated. (e.g., "gmail"). |
| account_identifier | string | The identifier of the account associated with the token.             |

---

##### Response

> `response` **DeleteEntityTokenResponse**

> [!IMPORTANT]
>
> The table lists only the fields that are populated for this step. Other fields
> may be empty, omitted, or false.

| Field   | Type   | Description                                |
| ------- | ------ | ------------------------------------------ |
| message | string | A response message from the server.        |
| success | bool   | Indicates if the operation was successful. |

---

##### Method

> `method` **DeleteEntityToken**

> [!TIP]
>
> The examples below use
> [grpcurl](https://github.com/fullstorydev/grpcurl#grpcurl).

> [!NOTE]
>
> Here is what a successful response from the server looks like.
>
> The server would return a status code of `0 OK` if the API transaction goes
> through without any friction. Otherwise, it will return any other code out of
> the
> [17 codes supported by gRPC](https://grpc.github.io/grpc/core/md_doc_statuscodes.html).

---

**Sample request**

```bash
grpcurl -plaintext \
    -d @ \
    -proto protos/v1/vault.proto \
localhost:6000 vault.v1.Entity/DeleteEntityToken <payload.json
```

---

**Sample payload.json**

```json
{
  "long_lived_token": "long_lived_token",
  "platform": "gmail",
  "account_identifier": "sample@mail.com"
}
```

---

**Sample response**

```json
{
  "message": "Token deleted successfully.",
  "success": true
}
```
