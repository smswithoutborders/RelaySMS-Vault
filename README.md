# RelaySMS Vault

RelaySMS Vault is a core unit in the RelaySMS ecosystem, responsible for authentication, authorization, secure storage, and message encryption/decryption. It ensures that access tokens (e.g., OAuth2 tokens from Gmail, Twitter, and Telegram phone-based authentication) and user data are securely managed while enabling authenticated message transmission.

## Table of Contents

1. [Overview](#overview)
2. [Configuration Guide](#configuration-guide)
3. [System Components](#system-components)
4. [References](#references)
   - [Security](#security)
   - [gRPC](#grpc)
   - [Specifications](#specifications)
     - [Long-Lived Tokens (LLTs)](#long-lived-tokens-llts)
     - [Device IDs](#device-ids)
     - [Auth Phrase](#auth-phrase)
   - [REST API Resources](#rest-api-resources)
5. [Contributing](#contributing)
6. [License](#license)

## Overview

RelaySMS Vault provides secure storage and access control for user authentication data and access tokens. It integrates with other RelaySMS units via gRPC to facilitate secure messaging.

Users create and manage their accounts through RelaySMS clients (apps), which interact with the vault to securely store and manage their authentication data. When sending messages, the vault ensures the user is authenticated before decrypting their access tokens and message content.

## Configuration Guide

## System Components

### **Entities (User Accounts)**

- Users register accounts via RelaySMS clients.
  - [Android](https://github.com/smswithoutborders/RelaySMS-Android)
  - [Desktop](https://github.com/smswithoutborders/RelaySMS-Desktop)
- Account information is securely stored in the vault.
- Users can delete and manage their accounts through the clients and gRPC.

### **Access Tokens**

- Users obtain access tokens via the [Publisher](https://github.com/smswithoutborders/RelaySMS-Publisher) unit.
- Tokens are securely stored in the vault and accessed via gRPC.

### **Message Handling**

- Messages are encrypted and decrypted using the **Signal Double Ratchet algorithm**.
- The vault and client use **X25519 key exchange** for secure asynchronous encryption.

## References

### [Security](docs/security.md)

For details on how RelaySMS Vault secures user data and tokens, see the [security documentation](./docs/security.md).

### [gRPC](docs/grpc.md)

RelaySMS Vault interacts with other RelaySMS units using gRPC. Learn more in the [gRPC documentation](docs/grpc.md).

### [Specifications](docs/specifications.md)

Technical details on vault implementation and integration:

- [Long-Lived Tokens (LLTs)](docs/specifications.md#1-long-lived-tokens-llts)
- [Device IDs](docs/specifications.md#2-device-id)
- [Auth Phrase](docs/specifications.md#3-auth-phrase)

### [REST API Resources](docs/api_versions.md)

API endpoints and available versions.

- [API V3](docs/api_v3.md)

## Contributing

To contribute:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-branch`.
3. Commit changes: `git commit -m 'Add a new feature'`.
4. Push to the branch: `git push origin feature-branch`.
5. Open a pull request.

## License

This project is licensed under the GNU General Public License (GPL). See the [LICENSE](LICENSE) file for details.
