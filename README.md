# RelaySMS Vault

RelaySMS Vault is the security core of the RelaySMS ecosystem, responsible for:

- **Authentication & Authorization:** Managing user access and permissions.
- **Access Token Management:** Secure storage and handling of tokens for supported protocols.
- **Data Security:** Encryption of sensitive data and secure message transmission.

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [References](#references)
6. [Contributing](#contributing)
7. [License](#license)

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

### Production Installation

Quick install with curl:

```bash
curl -fsSL https://raw.githubusercontent.com/smswithoutborders/RelaySMS-Vault/main/install.sh | sudo bash
```

Or with wget:

```bash
wget -qO- https://raw.githubusercontent.com/smswithoutborders/RelaySMS-Vault/main/install.sh | sudo bash
```

For detailed manual installation steps, see [INSTALL.md](INSTALL.md).

#### Manage Services

```bash
cd /opt/relaysms/relaysms-vault
./manage.sh {start|stop|restart|status|logs|update}
```

#### Configuration

Edit `/opt/relaysms/relaysms-vault/.env` and restart:

```bash
sudo ./manage.sh restart
```

##### Disable Mock OTP

For production, disable mock OTP to actually send OTP to users:

```bash
MOCK_OTP=false
```

##### Twilio Configuration

Configure Twilio to send SMS OTP. Get your credentials from [Twilio Console](https://www.twilio.com/console):

```bash
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_SERVICE_SID=your_service_sid
TWILIO_PHONE_NUMBER=your_twilio_phone_number
```

##### Email Service

Configure email OTP service. See [RelaySMS-Email-Service](https://github.com/smswithoutborders/RelaySMS-Email-Service) for setup and configuration details.

```bash
# Email Service Connection
EMAIL_SERVICE_URL=https://your-email-service.example.com
EMAIL_SERVICE_API_KEY=your_email_service_api_key

# Email Template Configuration
EMAIL_SUBJECT=Your verification code
EMAIL_ORGANIZATION_NAME=SMSWithoutBorders
EMAIL_WEBSITE_URL=https://relay.smswithoutborders.com
EMAIL_LOGO_URL=https://your-domain.com/logo.png
EMAIL_PROJECT_NAME=RelaySMS
EMAIL_ABUSE_EMAIL=abuse@smswithoutborders.com
EMAIL_SUPPORT_EMAIL=support@smswithoutborders.com

# Email Delivery
EMAIL_VERIFICATION_SENDER_ADDRESS=noreply@your-domain.com
EMAIL_OTP_EXPIRY_MINUTES=10
```

##### CAPTCHA Configuration

Configure CAPTCHA verification using [RelaySMS-CAPTCHA-Server](https://github.com/smswithoutborders/RelaySMS-CAPTCHA-Server), which uses [librecaptcha](https://github.com/librecaptcha/lc-core):

```bash
CAPTCHA_ENABLED=true
CAPTCHA_SERVER_URL=your_captcha_server_url
CAPTCHA_SECRET_KEY=your_captcha_secret_key
```

### Development Installation

For development, use the provided scripts:

```bash
source scripts/quick-setup.sh && ./scripts/quick-start.sh
```

- `quick-setup`:

  - Creates a Python virtual environment (if missing)
  - Installs Python dependencies
  - Sets up a `.env` file (SQLite by default)
  - Exports environment variables
  - Generates encryption and hashing keys
  - Compiles gRPC protos (via `make grpc-compile`)
  - Downloads supported platforms JSON (via `make download-platforms`)
  - Creates a dummy user (via `make create-dummy-user`)
  - Generates static x25519 keys (via `make generate-static-keys`)

- `quick-start`:
  - Launches the gRPC server, internal gRPC server, and REST server

> [!WARNING]
> This setup is for development only. Do not use in production.

## Building and Running with Docker

RelaySMS Vault provides two Docker stages: **production** and **development**.

### Development

#### Build the Docker Image

```bash
docker build --target development -t relaysms-vault:dev .
```

#### Prepare Environment Files

```bash
cp template.env .env && \
mkdir -p keys data && \
openssl rand -base64 32 > keys/encryption.key && \
openssl rand -base64 32 > keys/hashing.key && \
openssl rand -base64 32 > keys/pepper.key && \
openssl rand -base64 32 > keys/signing.key
```

> Edit `.env` as needed for your environment.

#### Run the Container

> [!TIP]
>
> **To allow external access to the container's gRPC network services, update `GRPC_HOST` from `localhost` to `0.0.0.0` in your `.env` file.**
>
> For example, run:
>
> ```bash
> sed -i 's/^GRPC_HOST=localhost/GRPC_HOST=0.0.0.0/' .env
> ```
>
> This ensures the gRPC server listens on all interfaces and is accessible from outside the container.
>
> **For long-term development, you may want to run the container in detached mode (`-d`) and view logs with:**
>
> ```bash
> docker logs -f <container_id_or_name>
> ```

```bash
docker run --rm --env-file .env -p 19000:19000 -p 8000:8000 -p 8443:8443 -v $(pwd)/data:/vault/data -v $(pwd)/keys:/vault/keys relaysms-vault:dev
```

> [!TIP]
>
> - To run in detached mode:
>
>   ```bash
>   docker run -d --name relaysms-vault-dev --env-file .env -p 19000:19000 -p 8000:8000 -p 8443:8443 -v $(pwd)/data:/vault/data -v $(pwd)/keys:/vault/keys relaysms-vault:dev
>   ```
>
> Then view logs with:
>
> ```bash
> docker logs -f relaysms-vault-dev
>   ```
>
> - REST API: `http://localhost:19000` or `https://localhost:19001`
> - gRPC server: `localhost:8000` (plaintext) or `localhost:8001` (SSL)
> - gRPC internal server: `localhost:8443` (plaintext) or `localhost:8444` (SSL)
>
> Expose SSL ports (`19001`, `8001`, `8444`) if you want to test SSL in development.

---

### Production

#### Build the Docker Image

```bash
docker build --target production -t relaysms-vault:prod .
```

#### Prepare Environment Files

```bash
cp template.env .env && \
mkdir -p keys data && \
openssl rand -base64 32 > keys/encryption.key && \
openssl rand -base64 32 > keys/hashing.key && \
openssl rand -base64 32 > keys/pepper.key && \
openssl rand -base64 32 > keys/signing.key
```

> Edit `.env` as needed for your environment.

#### Run the Container

> [!TIP]
>
> **To allow external access to the container's gRPC network services, update `GRPC_HOST` from `localhost` to `0.0.0.0` in your `.env` file.**
>
> For example, run:
>
> ```bash
> sed -i 's/^GRPC_HOST=localhost/GRPC_HOST=0.0.0.0/' .env
> ```
>
> This ensures the gRPC server listens on all interfaces and is accessible from outside the container.
>
> **For long-term production use, run in detached mode (`-d`) and view logs with:**
>
> ```bash
> docker logs -f <container_id_or_name>
> ```

```bash
docker run --rm \
  --env-file .env \
  -p 19000:19000 -p 19001:19001 \
  -p 8000:8000 -p 8001:8001 \
  -p 8443:8443 -p 8444:8444 \
  -v $(pwd)/data:/vault/data \
  -v $(pwd)/keys:/vault/keys \
  relaysms-vault:prod
```

> [!TIP]
>
> - To run in detached mode:
>
>   ```bash
>   docker run -d \
>     --name relaysms-vault-prod \
>     --env-file .env \
>     -p 19000:19000 -p 19001:19001 \
>     -p 8000:8000 -p 8001:8001 \
>     -p 8443:8443 -p 8444:8444 \
>     -v $(pwd)/data:/vault/data \
>     -v $(pwd)/keys:/vault/keys \
>     relaysms-vault:prod
>   ```
>
> Then view logs with:
>
> ```bash
> docker logs -f relaysms-vault-prod
>   ```
>
> - REST API: `https://localhost:19001`
> - gRPC server: `localhost:8001` (SSL)
> - gRPC internal server: `localhost:8444` (SSL)
>
> Plaintext ports (`19000`, `8000`, `8443`) are available for compatibility but SSL is enforced in production.

---

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

- `HOST`: REST server host (default: `localhost`)
- `PORT`: REST server port (default: `19000`)
- `SSL_PORT`: REST SSL port (default: `19001`)
- `SSL_CERTIFICATE`, `SSL_KEY`: SSL file paths (optional)

### gRPC

- `GRPC_HOST`: gRPC server host (default: `localhost`)
- `GRPC_PORT`: gRPC server port (default: `8000`)
- `GRPC_SSL_PORT`: gRPC SSL port (default: `8001`)
- `GRPC_INTERNAL_PORT`: Internal gRPC port (default: `8443`)
- `GRPC_INTERNAL_SSL_PORT`: Internal gRPC SSL port (default: `8444`)

### Security

- `DATA_ENCRYPTION_KEY_PRIMARY_FILE`: Path to 32-byte encryption key (default: `keys/encryption.key`)
- `HMAC_KEY_FILE`: Path to 32-byte HMAC key (default: `keys/hashing.key`)
- `PEPPER_FILE`: Path to 32-byte pepper key (default: `keys/pepper.key`)
- `SIGNATURE_KEY_FILE`: Path to 32-byte signing key (default: `keys/signing.key`)

### Database

- `MYSQL_HOST`: MySQL host (default: `127.0.0.1`)
- `MYSQL_USER`: MySQL username
- `MYSQL_PASSWORD`: MySQL password
- `MYSQL_DATABASE`: MySQL database (default: `relaysms_vault`)
- `SQLITE_DATABASE_PATH`: SQLite file path (default: `data/vault.db`)

### Twilio

- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_SERVICE_SID`, `TWILIO_PHONE_NUMBER`: Twilio credentials

### OTP

- `MOCK_OTP`: Enable mock OTP for development (`true` by default)
- `SMS_OTP_ENABLED`: Enable SMS OTP globally (default: `true`)
- `SMS_OTP_AUTH_ENABLED`: Enable SMS OTP for authentication (default: `true`)
- `SMS_OTP_SIGNUP_ENABLED`: Enable SMS OTP for signup (default: `true`)
- `SMS_OTP_RESET_PASSWORD_ENABLED`: Enable SMS OTP for password reset (default: `true`)
- `SMS_OTP_ALLOWED_COUNTRIES`: Comma-separated list of allowed country codes for SMS OTP
- `EMAIL_OTP_ENABLED`: Enable email OTP globally (default: `true`)
- `EMAIL_OTP_AUTH_ENABLED`: Enable email OTP for authentication (default: `true`)
- `EMAIL_OTP_SIGNUP_ENABLED`: Enable email OTP for signup (default: `true`)
- `EMAIL_OTP_RESET_PASSWORD_ENABLED`: Enable email OTP for password reset (default: `true`)
- `EMAIL_OTP_EXPIRY_MINUTES`: Email OTP expiration time in minutes (default: `10`)

### Captcha

- `CAPTCHA_ENABLED`: Enable captcha verification (default: `false`)
- `CAPTCHA_SERVER_URL`: Libre Captcha server URL
- `CAPTCHA_SECRET_KEY`: Captcha API secret key

### Keystore

- `KEYSTORE_PATH`: Keystore directory (default: `data/keystore`)
- `STATIC_X25519_KEYSTORE_PATH`: Static X25519 keystore (default: `data/keystore/static_x25519`)

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
