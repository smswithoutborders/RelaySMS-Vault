#!/bin/bash

SERVICE_NAME="relaysms-vault"
INSTALL_DIR="/opt/relaysms/relaysms-vault"

show_usage() {
  echo "Usage: $0 {start|stop|restart|status|logs|enable|disable|update|uninstall}"
  echo ""
  echo "Commands:"
  echo "  start      Start all services"
  echo "  stop       Stop all services"
  echo "  restart    Restart all services"
  echo "  status     Show status of all services"
  echo "  logs       Follow logs from all services"
  echo "  enable     Enable services on boot"
  echo "  disable    Disable services on boot"
  echo "  update     Update to latest version from repository"
  echo "  uninstall  Remove services and installation"
  exit 1
}

check_sudo() {
  if [ "$EUID" -ne 0 ]; then
    echo "This command requires root privileges. Use sudo."
    exit 1
  fi
}

case "$1" in
start)
  check_sudo
  systemctl start $SERVICE_NAME
  echo "Services started. Check status with: $0 status"
  ;;
stop)
  check_sudo
  systemctl stop $SERVICE_NAME
  echo "Services stopped."
  ;;
restart)
  check_sudo
  systemctl restart $SERVICE_NAME
  echo "Services restarted. Check status with: $0 status"
  ;;
status)
  systemctl status relaysms-vault-rest relaysms-vault-grpc relaysms-vault-grpc-internal
  ;;
logs)
  journalctl -u 'relaysms-vault*' -f
  ;;
enable)
  check_sudo
  systemctl enable $SERVICE_NAME
  echo "Services enabled on boot."
  ;;
disable)
  check_sudo
  systemctl disable $SERVICE_NAME
  echo "Services disabled on boot."
  ;;
update)
  check_sudo
  echo "Stopping services..."
  systemctl stop $SERVICE_NAME

  echo "Updating repository..."
  cd "$INSTALL_DIR"
  sudo -u relaysms git fetch origin
  sudo -u relaysms git pull origin main

  echo "Updating dependencies..."
  sudo -u relaysms venv/bin/pip install --upgrade pip
  sudo -u relaysms venv/bin/pip install -r requirements.txt

  echo "Recompiling gRPC protos..."
  sudo -u relaysms bash -c 'source venv/bin/activate && make grpc-compile'

  echo "Downloading platforms..."
  sudo -u relaysms bash -c 'source venv/bin/activate && make download-platforms'

  echo "Reloading systemd..."
  systemctl daemon-reload

  echo "Starting services..."
  systemctl start $SERVICE_NAME

  echo "Update complete. Check status with: $0 status"
  ;;
uninstall)
  check_sudo
  read -p "This will remove all services and data. Are you sure? (yes/no): " confirm
  if [ "$confirm" != "yes" ]; then
    echo "Uninstall cancelled."
    exit 0
  fi

  echo "Stopping services..."
  systemctl stop $SERVICE_NAME 2>/dev/null || true

  echo "Disabling services..."
  systemctl disable $SERVICE_NAME 2>/dev/null || true

  echo "Removing service files..."
  rm -f /etc/systemd/system/relaysms-vault*.service
  systemctl daemon-reload

  echo "Removing installation directory..."
  rm -rf "$INSTALL_DIR"

  read -p "Remove system user 'relaysms'? (yes/no): " remove_user
  if [ "$remove_user" = "yes" ]; then
    userdel -r relaysms 2>/dev/null || true
    echo "User removed."
  fi

  echo "Uninstall complete."
  ;;
*)
  show_usage
  ;;
esac
