# RelaySMS Vault

RelaySMS Vault is the security core of the RelaySMS ecosystem, responsible for:

- **Authentication & Authorization:** Managing user access and permissions.
- **Access Token Management:** Secure storage and handling of tokens for supported protocols.
- **Data Security:** Encryption of sensitive data and secure message transmission.

## Table of Contents

1. [Quick Start](#quick-start)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [References](#references)
6. [Contributing](#contributing)
7. [License](#license)

## Quick Start

> [!NOTE]
>
> Ensure all [system dependencies](#system-requirements) are installed before running setup scripts.

For development, use the provided scripts:

```bash
source scripts/quick-setup
./scripts/quick-start
```

- `quick-setup`:

  - Creates a Python virtual environment (if missing)
  - Installs Python dependencies
  - Sets up a `.env` file (SQLite by default)
  - Exports environment variables
  - Generates encryption and hashing keys

- `quick-start`:
  - Launches the gRPC server, internal gRPC server, and REST server

> [!WARNING]
>
> This setup is for development only. Do not use in production.

## System Requirements

- **Database:** MySQL (≥ 8.0.28), MariaDB, or SQLite
- **Python:** ≥ 3.8.10
- **Virtual Environments:** Python venv

### Ubuntu Dependencies

```bash
sudo apt update
sudo apt install python3-dev libmysqlclient-dev apache2 apache2-dev make libapache2-mod-wsgi-py3
```

## Installation

1. **Create and activate a virtual environment:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

Configure via environment variables, either in your shell or a `.env` file.

**To load from `.env`:**

```bash
set -a
source .env
set +a
```

**Or set individually:**

```bash
export HOST=localhost
export PORT=19000
# etc.
```

### Server

- `SSL_SERVER_NAME`: SSL certificate server name (default: `localhost`)
- `HOST`: REST server host (default: `localhost`)
- `PORT`: REST server port (default: `19000`)
- `SSL_PORT`: REST SSL port (default: `19001`)
- `SSL_CERTIFICATE`, `SSL_KEY`, `SSL_PEM`: SSL file paths (optional)

### gRPC

- `GRPC_HOST`: gRPC server host (default: `localhost`)
- `GRPC_PORT`: gRPC server port (default: `8000`)
- `GRPC_SSL_PORT`: gRPC SSL port (default: `8001`)
- `GRPC_INTERNAL_PORT`: Internal gRPC port (default: `8443`)
- `GRPC_INTERNAL_SSL_PORT`: Internal gRPC SSL port (default: `8444`)

### Security

- `SHARED_KEY`: Path to 32-byte encryption key (default: `encryption.key`)
- `HASHING_SALT`: Path to 32-byte hashing salt (default: `hashing.key`)

### Database

- `MYSQL_HOST`: MySQL host (default: `127.0.0.1`)
- `MYSQL_USER`: MySQL username
- `MYSQL_PASSWORD`: MySQL password
- `MYSQL_DATABASE`: MySQL database (default: `relaysms_vault`)
- `SQLITE_DATABASE_PATH`: SQLite file path (default: `vault.db`)

### Twilio

- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_SERVICE_SID`, `TWILIO_PHONE_NUMBER`: Twilio credentials

### OTP

- `MOCK_OTP`: Enable mock OTP for development (`true` by default)

### CORS

- `ORIGINS`: Allowed CORS origins (default: `[]`)

### Keystore

- `KEYSTORE_PATH`: Keystore directory (default: `keystore`)
- `STATIC_X25519_KEYSTORE_PATH`: Static X25519 keystore (default: `keystore/static_x25519`)

### Logging

- `LOG_LEVEL`: Logging level (default: `info`)

### Dummy Data

- `DUMMY_PHONENUMBERS`: Test phone numbers (default: `+237123456789`)
- `DUMMY_PASSWORD`: Test password (default: `dummy_password`)

## References

- [Security](docs/security.md): Vault security details
- [gRPC](docs/grpc.md): gRPC integration and usage
- [Specifications](docs/specifications.md):
  - [Long-Lived Tokens (LLTs)](docs/specifications.md#1-long-lived-tokens-llts)
  - [Device IDs](docs/specifications.md#2-device-id)
  - [Auth Phrase](docs/specifications.md#3-auth-phrase)
- [REST API Resources](docs/api_versions.md):
  - [API V3](docs/api_v3.md)

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-branch`
3. Commit your changes
4. Push to your branch
5. Open a pull request

## License

Licensed under the GNU General Public License (GPL). See [LICENSE](LICENSE) for details.
