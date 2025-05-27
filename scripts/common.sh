#!/bin/bash

SCRIPT_DIR=$(dirname $(readlink -f ${BASH_SOURCE[0]}))
source "${SCRIPT_DIR}/logger.sh" || exit 1

load_env() {
    local env_file=$1

    if [ -f $env_file ]; then
        logger INFO "Loading environment variables from $env_file."
        set -a
        source $env_file
        set +a
    else
        logger WARNING "Environment file not found at $env_file. Skipping loading."
    fi
}

generate_base64_key() {
    local output_path=$1

    if [ -z "$output_path" ]; then
        logger ERROR "Output file path is required."
        return 1
    fi

    openssl rand -base64 32 >"$output_path"
    if [ $? -eq 0 ]; then
        logger INFO "32-byte base64 key generated and saved to $output_path."
    else
        logger ERROR "Failed to generate base64 key."
        return 1
    fi
}
