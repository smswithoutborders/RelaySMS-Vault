#!/bin/bash

# Script for quick setup.
# Use for development purposes only.

SCRIPT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
PARENT_DIR=$(dirname $SCRIPT_DIR)
source "${SCRIPT_DIR}/logger.sh" || exit 1
source "${SCRIPT_DIR}/common.sh" || exit 1

VENV_PATH="${PARENT_DIR}/venv"
ENV_FILE_PATH="${PARENT_DIR}/.env"
ENV_TEMPLATE_PATH="${PARENT_DIR}/template.env"
REQUIREMENTS_FILE_PATH="${PARENT_DIR}/requirements.txt"

if [ -d $VENV_PATH ]; then
  logger INFO "Virtual environment already exists at $VENV_PATH. Skipping creation."
else
  logger INFO "Creating virtual environment at $VENV_PATH."
  python3 -m venv "$VENV_PATH" || {
    logger ERROR "Failed to create virtual environment."
    exit 1
  }
fi
source "$VENV_PATH/bin/activate" || {
  logger ERROR "Failed to activate virtual environment."
  exit 1
}
if [ -f $REQUIREMENTS_FILE_PATH ]; then
  logger INFO "Installing requirements from $REQUIREMENTS_FILE_PATH."
  pip install -r "$REQUIREMENTS_FILE_PATH" || {
    logger ERROR "Failed to install requirements."
    exit 1
  }
else
  logger WARNING "Requirements file not found at $REQUIREMENTS_FILE_PATH. Skipping installation."
fi
if [ ! -f $ENV_FILE_PATH ]; then
  logger INFO "Creating .env file at $ENV_FILE_PATH."
  cp $ENV_TEMPLATE_PATH $ENV_FILE_PATH || {
    logger ERROR "Failed to create .env file."
    exit 1
  }
else
  logger INFO ".env file already exists at $ENV_FILE_PATH. Skipping creation."
fi
load_env $ENV_FILE_PATH
logger WARNING "Run 'deactivate' to exit the virtual environment."

if [ ! -f $DATA_ENCRYPTION_KEY_PRIMARY_FILE ]; then
  logger INFO "Encryption key file not found at $DATA_ENCRYPTION_KEY_PRIMARY_FILE. Generating new key."
  generate_base64_key $DATA_ENCRYPTION_KEY_PRIMARY_FILE || {
    logger ERROR "Failed to generate encryption key."
    exit 1
  }
else
  logger INFO "Encryption key file already exists at $DATA_ENCRYPTION_KEY_PRIMARY_FILE. Skipping key generation."
fi

if [ ! -f $HMAC_KEY_FILE ]; then
  logger INFO "HMAC key file not found at $HMAC_KEY_FILE. Generating new key."
  generate_base64_key $HMAC_KEY_FILE || {
    logger ERROR "Failed to generate HMAC key."
    exit 1
  }
else
  logger INFO "HMAC key file already exists at $HMAC_KEY_FILE. Skipping key generation."
fi

if [ ! -f $PEPPER_FILE ]; then
  logger INFO "Pepper file not found at $PEPPER_FILE. Generating new pepper."
  generate_base64_key $PEPPER_FILE || {
    logger ERROR "Failed to generate pepper."
    exit 1
  }
else
  logger INFO "Pepper file already exists at $PEPPER_FILE. Skipping pepper generation."
fi

if [ ! -f $SIGNATURE_KEY_FILE ]; then
  logger INFO "JWT signing key file not found at $SIGNATURE_KEY_FILE. Generating new key."
  generate_base64_key $SIGNATURE_KEY_FILE || {
    logger ERROR "Failed to generate JWT signing key."
    exit 1
  }
else
  logger INFO "JWT signing key file already exists at $SIGNATURE_KEY_FILE. Skipping key generation."
fi

logger INFO "Running 'make build-setup'."
make build-setup || {
  logger ERROR "'make build-setup' failed."
  exit 1
}

logger INFO "Running 'make runtime-setup'."
make runtime-setup || {
  logger ERROR "'make runtime-setup' failed."
  exit 1
}

logger INFO "Quick setup completed successfully."
