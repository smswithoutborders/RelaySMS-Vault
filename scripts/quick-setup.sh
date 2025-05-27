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

if [ ! -f $SHARED_KEY ]; then
    logger INFO "Shared key file not found at $SHARED_KEY. Generating new keys."
    generate_base64_key $SHARED_KEY || {
        logger ERROR "Failed to generate shared key."
        exit 1
    }
else
    logger INFO "Shared key file already exists at $SHARED_KEY. Skipping key generation."
fi

if [ ! -f $HASHING_SALT ]; then
    logger INFO "Hashing salt file not found at $HASHING_SALT. Generating new salt."
    generate_base64_key $HASHING_SALT || {
        logger ERROR "Failed to generate hashing salt."
        exit 1
    }
else
    logger INFO "Hashing salt file already exists at $HASHING_SALT. Skipping salt generation."
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
