# Installation Guide

## Install Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-dev \
    libmysqlclient-dev git curl make openssl gettext-base
```

## Clone Repository

```bash
sudo mkdir -p /opt/relaysms
sudo git clone https://github.com/smswithoutborders/RelaySMS-Vault.git \
    /opt/relaysms/relaysms-vault
cd /opt/relaysms/relaysms-vault
sudo chown -R $USER:$USER /opt/relaysms/relaysms-vault
```

## Setup Python Environment

```bash
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt
```

## Build Application

```bash
source venv/bin/activate && make grpc-compile
source venv/bin/activate && make download-platforms
```

## Configure Environment

```bash
cp template.env .env
# Edit .env as needed
vim .env
```

## Generate Security Keys

```bash
mkdir -p keys
openssl rand -base64 32 > keys/encryption.key
openssl rand -base64 32 > keys/hashing.key
openssl rand -base64 32 > keys/pepper.key
openssl rand -base64 32 > keys/signing.key
chmod 700 keys
chmod 600 keys/*.key
```

## Create Data Directory

```bash
mkdir -p data
```

## Runtime Setup

```bash
venv/bin/activate && set -a && source .env && set +a && make runtime-setup
```

### Install Services

```bash
# Substitute user and group in service files
export USER=$USER
export GROUP=$(id -gn)
for service in relaysms-vault.target relaysms-vault-rest.service relaysms-vault-grpc.service relaysms-vault-grpc-internal.service; do
    envsubst < $service | sudo tee /etc/systemd/system/$service > /dev/null
done
sudo systemctl daemon-reload
sudo systemctl enable relaysms-vault.target
```

### Set Permissions

```bash
sudo chown -R $USER:$USER /opt/relaysms/relaysms-vault
chmod -R 750 /opt/relaysms/relaysms-vault
chmod 700 /opt/relaysms/relaysms-vault/keys
chmod 600 /opt/relaysms/relaysms-vault/keys/*.key
chmod 600 /opt/relaysms/relaysms-vault/.env
```

### Start Services

```bash
sudo systemctl start relaysms-vault.target
```

## Service Architecture

- `relaysms-vault.target` - Main coordination target
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
./manage.sh start|stop|restart|status|logs|enable|disable

# Direct systemd
sudo systemctl start relaysms-vault.target
sudo systemctl status relaysms-vault.target
journalctl -u 'relaysms-vault*' -f
```

## Update

```bash
sudo systemctl stop relaysms-vault.target
cd /opt/relaysms/relaysms-vault
git pull
venv/bin/pip install -r requirements.txt
source venv/bin/activate && make grpc-compile
sudo systemctl start relaysms-vault.target
```

## Uninstall

```bash
sudo systemctl stop relaysms-vault.target
sudo systemctl disable relaysms-vault.target
sudo rm /etc/systemd/system/relaysms-vault*.{service,target}
sudo systemctl daemon-reload
sudo rm -rf /opt/relaysms/relaysms-vault
```

## File Locations

- Installation: `/opt/relaysms/relaysms-vault/`
- Configuration: `/opt/relaysms/relaysms-vault/.env`
- Security keys: `/opt/relaysms/relaysms-vault/keys/`
- Data directory: `/opt/relaysms/relaysms-vault/data/`
  - Database: `/opt/relaysms/relaysms-vault/data/vault.db`
  - Keystores: `/opt/relaysms/relaysms-vault/data/keystore/`
- Services: `/etc/systemd/system/relaysms-vault.target` and `/etc/systemd/system/relaysms-vault*.service`
- Logs: `journalctl -u relaysms-vault*`
