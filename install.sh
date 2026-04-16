#!/bin/bash

set -e

INSTALL_DIR="/opt/relaysms/relaysms-vault"
SERVICE_NAME="relaysms-vault"
REPO_URL="https://github.com/smswithoutborders/RelaySMS-Vault.git"
BRANCH="${BRANCH:-main}"
USER="relaysms"
GROUP="relaysms"

log() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

error() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
  exit 1
}

check_root() {
  if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root"
  fi
}

install_dependencies() {
  log "Installing system dependencies"
  apt update || error "Failed to update package list"
  apt install -y python3 python3-pip python3-venv python3-dev \
    libmysqlclient-dev git curl make openssl || error "Failed to install dependencies"
}

create_user() {
  if ! id "$USER" &>/dev/null; then
    log "Creating system user: $USER"
    useradd --system --shell /bin/bash --home-dir "$INSTALL_DIR" \
      --create-home --user-group "$USER" || error "Failed to create user"
  else
    log "User $USER already exists"
  fi
}

clone_repository() {
  log "Cloning repository from $REPO_URL (branch: $BRANCH)"

  if [ -d "$INSTALL_DIR/.git" ]; then
    log "Repository already exists, updating"
    cd "$INSTALL_DIR"
    sudo -u "$USER" git fetch origin || error "Failed to fetch updates"
    sudo -u "$USER" git checkout "$BRANCH" || error "Failed to checkout branch $BRANCH"
    sudo -u "$USER" git pull origin "$BRANCH" || error "Failed to pull updates"
  else
    mkdir -p "$(dirname "$INSTALL_DIR")"
    sudo -u "$USER" git clone -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR" || error "Failed to clone repository"
  fi
}

setup_virtualenv() {
  log "Setting up Python virtual environment"
  cd "$INSTALL_DIR"

  if [ ! -d "venv" ]; then
    sudo -u "$USER" python3 -m venv venv || error "Failed to create virtual environment"
  fi

  log "Installing Python dependencies"
  sudo -u "$USER" venv/bin/pip install --upgrade pip || error "Failed to upgrade pip"
  sudo -u "$USER" venv/bin/pip install -r requirements.txt || error "Failed to install requirements"
}

compile_grpc() {
  log "Compiling gRPC protos"
  cd "$INSTALL_DIR"
  sudo -u "$USER" bash -c 'source venv/bin/activate && make grpc-compile' || error "Failed to compile gRPC"
}

download_platforms() {
  log "Downloading platforms JSON"
  cd "$INSTALL_DIR"
  sudo -u "$USER" bash -c 'source venv/bin/activate && make download-platforms' || error "Failed to download platforms"
}

setup_env() {
  log "Setting up environment configuration"
  cd "$INSTALL_DIR"

  if [ ! -f ".env" ]; then
    if [ -f "template.env" ]; then
      log "Copying template.env to .env"
      sudo -u "$USER" cp template.env .env
    else
      error "template.env not found in repository"
    fi
  else
    log "Environment file .env already exists"
  fi
}

generate_keys() {
  log "Generating security keys"
  cd "$INSTALL_DIR"

  if [ ! -d "keys" ]; then
    sudo -u "$USER" mkdir -p keys
  fi

  if [ ! -f "keys/encryption.key" ]; then
    openssl rand -base64 32 >keys/encryption.key
    chown "$USER:$GROUP" keys/encryption.key
    chmod 600 keys/encryption.key
  fi

  if [ ! -f "keys/hashing.key" ]; then
    openssl rand -base64 32 >keys/hashing.key
    chown "$USER:$GROUP" keys/hashing.key
    chmod 600 keys/hashing.key
  fi

  if [ ! -f "keys/pepper.key" ]; then
    openssl rand -base64 32 >keys/pepper.key
    chown "$USER:$GROUP" keys/pepper.key
    chmod 600 keys/pepper.key
  fi

  if [ ! -f "keys/signing.key" ]; then
    openssl rand -base64 32 >keys/signing.key
    chown "$USER:$GROUP" keys/signing.key
    chmod 600 keys/signing.key
  fi
}

setup_runtime() {
  log "Setting up runtime environment"
  cd "$INSTALL_DIR"

  if [ ! -d "data" ]; then
    sudo -u "$USER" mkdir -p data
  fi

  sudo -u "$USER" bash -c 'source venv/bin/activate && export $(cat .env | xargs) && make runtime-setup' || log "Runtime setup completed with warnings"
}

install_systemd_service() {
  log "Installing systemd service units"

  for service in relaysms-vault.service relaysms-vault-rest.service relaysms-vault-grpc.service relaysms-vault-grpc-internal.service; do
    if [ ! -f "$INSTALL_DIR/$service" ]; then
      error "Service file $service not found in repository"
    fi
    cp "$INSTALL_DIR/$service" /etc/systemd/system/ || error "Failed to copy $service"
  done

  systemctl daemon-reload || error "Failed to reload systemd"
  systemctl enable "$SERVICE_NAME" || error "Failed to enable service"
}

set_permissions() {
  log "Setting file permissions"
  chown -R "$USER:$GROUP" "$INSTALL_DIR" || error "Failed to set ownership"
  chmod -R 750 "$INSTALL_DIR" || error "Failed to set permissions"
  chmod 700 "$INSTALL_DIR/keys" 2>/dev/null || true
  chmod 600 "$INSTALL_DIR/keys"/*.key 2>/dev/null || true
  chmod 600 "$INSTALL_DIR/.env" 2>/dev/null || true
  chmod -R 750 "$INSTALL_DIR/data" 2>/dev/null || true
}

main() {
  log "Starting RelaySMS Vault installation"

  check_root
  install_dependencies
  create_user
  clone_repository
  setup_virtualenv
  compile_grpc
  download_platforms
  setup_env
  generate_keys
  setup_runtime
  set_permissions
  install_systemd_service

  log "Installation complete"
  log ""
  log "Use the manage.sh script to control services:"
  log "  $INSTALL_DIR/manage.sh start|stop|restart|status|logs"
  log ""
  log "Configuration file: $INSTALL_DIR/.env"
}

main "$@"
