#!/bin/bash

SERVICE_NAME="relaysms-vault.target"
INSTALL_DIR="/opt/relaysms/relaysms-vault"

check_sudo() {
  [ "$EUID" -eq 0 ] || {
    echo "Requires sudo"
    exit 1
  }
}

case "$1" in
start)
  check_sudo
  systemctl start $SERVICE_NAME
  echo "Services started"
  ;;
stop)
  check_sudo
  systemctl stop $SERVICE_NAME
  echo "Services stopped"
  ;;
restart)
  check_sudo
  systemctl restart $SERVICE_NAME
  echo "Services restarted"
  ;;
status)
  systemctl status relaysms-vault-rest relaysms-vault-grpc relaysms-vault-grpc-internal
  ;;
logs)
  journalctl -u relaysms-vault-rest -u relaysms-vault-grpc -u relaysms-vault-grpc-internal -f
  ;;
enable)
  check_sudo
  systemctl enable $SERVICE_NAME
  echo "Services enabled on boot"
  ;;
disable)
  check_sudo
  systemctl disable $SERVICE_NAME
  echo "Services disabled on boot"
  ;;
update)
  check_sudo
  systemctl stop $SERVICE_NAME
  cd "$INSTALL_DIR"
  git pull
  source venv/bin/activate
  pip install --upgrade pip
  pip install -r requirements.txt
  make grpc-compile
  make download-platforms
  systemctl daemon-reload
  systemctl start $SERVICE_NAME
  echo "Update complete"
  ;;
uninstall)
  check_sudo
  read -p "Remove all services and data? (yes/no): " confirm
  [ "$confirm" != "yes" ] && echo "Cancelled" && exit 0
  systemctl stop $SERVICE_NAME 2>/dev/null || true
  systemctl disable $SERVICE_NAME 2>/dev/null || true
  rm -f /etc/systemd/system/relaysms-vault*.{service,target}
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR"
  echo "Uninstall complete"
  ;;
*)
  echo "Usage: $0 {start|stop|restart|status|logs|enable|disable|update|uninstall}"
  exit 1
  ;;
esac
