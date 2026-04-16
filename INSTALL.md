# Installation Guide

## Automated Installation

```bash
sudo ./install.sh
```

This will:

- Install system dependencies
- Clone repository to `/opt/relaysms/relaysms-vault`
- Setup Python virtualenv
- Compile gRPC protos
- Download platform configurations
- Generate security keys
- Install and enable systemd services

## Manual Installation

### Install Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv python3-dev \
    libmysqlclient-dev git curl make openssl
```

### Clone Repository

```bash
sudo git clone https://github.com/smswithoutborders/RelaySMS-Vault.git \
    /opt/relaysms/relaysms-vault
cd /opt/relaysms/relaysms-vault
```

### Setup Python Environment

```bash
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt
```

### Build Application

```bash
source venv/bin/activate
make grpc-compile
make download-platforms
```

### Configure Environment

```bash
cp template.env .env
vim .env
```

### Generate Security Keys

```bash
mkdir -p keys
openssl rand -base64 32 > keys/encryption.key
openssl rand -base64 32 > keys/hashing.key
openssl rand -base64 32 > keys/pepper.key
openssl rand -base64 32 > keys/signing.key
chmod 700 keys
chmod 600 keys/*.key
chmod 600 .env
```

### Initialize Runtime

```bash
mkdir -p data
set -a && source .env && set +a
make runtime-setup
```

### Install Services

```bash
sudo cp relaysms-vault.target relaysms-vault-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable relaysms-vault.target
sudo systemctl start relaysms-vault.target
```

## Service Management

```bash
./manage.sh start       # Start all services
./manage.sh stop        # Stop all services
./manage.sh restart     # Restart all services
./manage.sh status      # Check status
./manage.sh logs        # View logs
./manage.sh enable      # Enable on boot
./manage.sh disable     # Disable on boot
./manage.sh update      # Update installation
./manage.sh uninstall   # Remove installation
```

## Configuration

Edit `/opt/relaysms/relaysms-vault/.env`:

## Services

- `relaysms-vault-rest.service` - REST API (default port 19000)
- `relaysms-vault-grpc.service` - gRPC server (port 8000)
- `relaysms-vault-grpc-internal.service` - Internal gRPC (port 8443)
- `relaysms-vault.target` - Service group

## File Locations

- Installation: `/opt/relaysms/relaysms-vault/`
- Configuration: `/opt/relaysms/relaysms-vault/.env`
- Security keys: `/opt/relaysms/relaysms-vault/keys/`
- Database: `/opt/relaysms/relaysms-vault/data/vault.db`
- Keystores: `/opt/relaysms/relaysms-vault/data/keystore/`
- Service files: `/etc/systemd/system/relaysms-vault*`
