# Manual Installation Guide

## What the install.sh script does

1. Installs dependencies: python3, python3-venv, libmysqlclient-dev, git, curl, make, openssl
2. Creates system user `relaysms`
3. Clones repository to `/opt/relaysms/relaysms-vault/`
4. Sets up Python virtual environment
5. Installs Python dependencies
6. Compiles gRPC protos
7. Downloads platforms JSON
8. Copies `template.env` to `.env`
9. Generates security keys with OpenSSL
10. Creates data directory for SQLite
11. Runs runtime setup (creates dummy user, generates x25519 keys)
12. Installs systemd service files
13. Enables services on boot

## Manual Steps

### Install Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-dev \
    libmysqlclient-dev git curl make openssl
```

### Create User

```bash
sudo useradd --system --shell /bin/bash --home-dir /opt/relaysms/relaysms-vault \
    --create-home --user-group relaysms
```

### Clone Repository

```bash
sudo -u relaysms git clone https://github.com/smswithoutborders/RelaySMS-Vault.git \
    /opt/relaysms/relaysms-vault
cd /opt/relaysms/relaysms-vault
```

### Setup Python Environment

```bash
sudo -u relaysms python3 -m venv venv
sudo -u relaysms venv/bin/pip install --upgrade pip
sudo -u relaysms venv/bin/pip install -r requirements.txt
```

### Build Application

```bash
sudo -u relaysms bash -c 'source venv/bin/activate && make grpc-compile'
sudo -u relaysms bash -c 'source venv/bin/activate && make download-platforms'
```

### Configure Environment

```bash
sudo -u relaysms cp template.env .env
# Edit .env as needed
sudo vim .env
```

### Generate Security Keys

```bash
sudo -u relaysms mkdir -p keys
sudo -u relaysms sh -c 'openssl rand -base64 32 > keys/encryption.key'
sudo -u relaysms sh -c 'openssl rand -base64 32 > keys/hashing.key'
sudo -u relaysms sh -c 'openssl rand -base64 32 > keys/pepper.key'
sudo -u relaysms sh -c 'openssl rand -base64 32 > keys/signing.key'
sudo chmod 700 keys
sudo chmod 600 keys/*.key
```

### Create Data Directory

```bash
sudo -u relaysms mkdir -p data
```

### Runtime Setup

```bash
sudo -u relaysms bash -c 'source venv/bin/activate && export $(cat .env | xargs) && make runtime-setup'
```

### Install Services

```bash
sudo cp relaysms-vault*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable relaysms-vault
```

### Set Permissions

```bash
sudo chown -R relaysms:relaysms /opt/relaysms/relaysms-vault
sudo chmod -R 750 /opt/relaysms/relaysms-vault
sudo chmod 700 /opt/relaysms/relaysms-vault/keys
sudo chmod 600 /opt/relaysms/relaysms-vault/keys/*.key
sudo chmod 600 /opt/relaysms/relaysms-vault/.env
```

### Start Services

```bash
sudo systemctl start relaysms-vault
```

## Service Architecture

- `relaysms-vault.service` - Main target
- `relaysms-vault-rest.service` - REST API (port 19000)
- `relaysms-vault-grpc.service` - gRPC server (port 8000)
- `relaysms-vault-grpc-internal.service` - Internal gRPC (port 8443)

## Configuration

Edit `/opt/relaysms/relaysms-vault/.env`:

```bash
# Bind to localhost for reverse proxy, 0.0.0.0 for direct access
HOST=127.0.0.1
PORT=19000

# Database (SQLite default, stored in data/ directory)
SQLITE_DATABASE_PATH=data/vault.db

# Keystore (cryptographic keys stored in data/ directory)
KEYSTORE_PATH=data/keystore
STATIC_X25519_KEYSTORE_PATH=data/keystore/static_x25519

# Or use MySQL
MYSQL_HOST=127.0.0.1
MYSQL_USER=vault_user
MYSQL_PASSWORD=secure_password
MYSQL_DATABASE=relaysms_vault
```

## Service Management

```bash
# Using manage.sh
sudo ./manage.sh start|stop|restart|status|logs|enable|disable

# Direct systemd
sudo systemctl start relaysms-vault
sudo systemctl status relaysms-vault
journalctl -u 'relaysms-vault*' -f
```

## Update

```bash
sudo systemctl stop relaysms-vault
cd /opt/relaysms/relaysms-vault
sudo -u relaysms git pull
sudo -u relaysms venv/bin/pip install -r requirements.txt
sudo -u relaysms bash -c 'source venv/bin/activate && make grpc-compile'
sudo systemctl start relaysms-vault
```

## Uninstall

```bash
sudo systemctl stop relaysms-vault
sudo systemctl disable relaysms-vault
sudo rm /etc/systemd/system/relaysms-vault*.service
sudo systemctl daemon-reload
sudo rm -rf /opt/relaysms/relaysms-vault
sudo userdel relaysms
```

## File Locations

- Installation: `/opt/relaysms/relaysms-vault/`
- Configuration: `/opt/relaysms/relaysms-vault/.env`
- Security keys: `/opt/relaysms/relaysms-vault/keys/`
- Data directory: `/opt/relaysms/relaysms-vault/data/`
  - Database: `/opt/relaysms/relaysms-vault/data/vault.db`
  - Keystores: `/opt/relaysms/relaysms-vault/data/keystore/`
- Services: `/etc/systemd/system/relaysms-vault*.service`
- Logs: `journalctl -u relaysms-vault*`
