#!/bin/bash

set -e

INSTALL_DIR="/opt/relaysms/relaysms-vault"
SERVICE_NAME="relaysms-vault"
REPO_URL="https://github.com/smswithoutborders/RelaySMS-Vault.git"
BRANCH="${BRANCH:-main}"
USER="${SUDO_USER:-$(whoami)}"
GROUP="$(id -gn $USER)"

log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"; }
error() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1" >&2
  exit 1
}
check_root() { [ "$EUID" -eq 0 ] || error "This script must be run with sudo"; }

install_dependencies() {
  log "Installing dependencies"
  apt update || error "Failed to update package list"
  apt install -y python3 python3-pip python3-venv python3-dev \
    libmysqlclient-dev git curl make openssl gettext-base || error "Failed to install dependencies"
}

clone_repository() {
  log "Cloning repository"
  if [ -d "$INSTALL_DIR/.git" ]; then
    log "Repository exists, updating"
    cd "$INSTALL_DIR"
    git fetch origin && git checkout "$BRANCH" && git pull origin "$BRANCH" || error "Failed to update"
  else
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone -b "$BRANCH" "$REPO_URL" "$INSTALL_DIR" || error "Failed to clone"
    chown -R "$USER:$GROUP" "$INSTALL_DIR"
  fi
}

setup_virtualenv() {
  log "Setting up virtual environment"
  cd "$INSTALL_DIR"
  [ -d "venv" ] || python3 -m venv venv || error "Failed to create venv"
  venv/bin/pip install --upgrade pip || error "Failed to upgrade pip"
  venv/bin/pip install -r requirements.txt || error "Failed to install dependencies"
}

compile_grpc() {
  log "Compiling gRPC protos"
  make grpc-compile || error "Failed to compile gRPC"
}

download_platforms() {
  log "Downloading platforms"
  make download-platforms || error "Failed to download platforms"
}

setup_env() {
  log "Setting up configuration"
  [ -f ".env" ] && log ".env already exists" && return
  [ -f "template.env" ] || error "template.env not found"
  cp template.env .env
}

generate_keys() {
  log "Generating keys"
  mkdir -p keys
  for key in encryption hashing pepper signing; do
    [ -f "keys/$key.key" ] || openssl rand -base64 32 >"keys/$key.key"
  done
  chown -R "$USER:$GROUP" keys
  chmod 700 keys
  chmod 600 keys/*.key
}

setup_runtime() {
  log "Setting up runtime"
  mkdir -p data
  set -a && source .env && set +a
  make runtime-setup || log "Runtime setup completed with warnings"
}

install_systemd_service() {
  log "Installing systemd services"
  for service in relaysms-vault.target relaysms-vault-rest.service relaysms-vault-grpc.service relaysms-vault-grpc-internal.service; do
    [ -f "$service" ] || error "Service file $service not found"
    envsubst <"$service" >/etc/systemd/system/$service || error "Failed to install $service"
  done
  systemctl daemon-reload && systemctl enable "$SERVICE_NAME.target" || error "Failed to enable services"
}

set_permissions() {
  log "Setting permissions"
  chown -R "$USER:$GROUP" "$INSTALL_DIR"
  chmod -R 750 "$INSTALL_DIR"
  chmod 700 keys 2>/dev/null || true
  chmod 600 keys/*.key 2>/dev/null || true
  chmod 600 .env 2>/dev/null || true
}

main() {
  log "Starting installation"

  check_root
  install_dependencies
  clone_repository
  setup_virtualenv

  cd "$INSTALL_DIR"
  source venv/bin/activate

  compile_grpc
  download_platforms
  setup_env
  generate_keys
  setup_runtime
  set_permissions
  install_systemd_service

  log "Installation complete"
  log "Manage services: $INSTALL_DIR/manage.sh {start|stop|restart|status|logs}"
  log "Configuration: $INSTALL_DIR/.env"
}

main "$@"
