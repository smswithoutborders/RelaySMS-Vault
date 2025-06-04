# This program is free software: you can redistribute it under the terms
# of the GNU General Public License, v. 3.0. If a copy of the GNU General
# Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.

PYTHON := python3
SUPPORTED_PLATFORMS_URL="https://raw.githubusercontent.com/smswithoutborders/SMSWithoutBorders-Publisher/main/resources/platforms.json"

define log_message
	@echo "[$(shell date +'%Y-%m-%d %H:%M:%S')] $(1)"
endef

start-rest-api:
	$(call log_message,[INFO] Starting REST API ...)
	@if [ "$$MODE" = "production" ]; then \
		echo "[INFO] Running in production mode with SSL"; \
		gunicorn -w 4 -b 0.0.0.0:$$SSL_PORT \
			--log-level=info \
			--access-logfile=- \
			--certfile=$$SSL_CERTIFICATE \
			--keyfile=$$SSL_KEY \
			--threads 15 \
			--timeout 30 \
			app:app; \
	else \
		echo "[INFO] Running in development mode without SSL"; \
		gunicorn -w 1 -b 0.0.0.0:$$PORT \
			--log-level=info \
			--access-logfile=- \
			--threads 3 \
			--timeout 30 \
			app:app; \
	fi
	$(call log_message,[INFO] REST API started successfully.)

grpc-compile:
	$(call log_message,[INFO] Compiling gRPC protos ...)
	@$(PYTHON) -m grpc_tools.protoc \
		-I./protos/v1 \
		--python_out=. \
		--pyi_out=. \
		--grpc_python_out=. \
		./protos/v1/*.proto
	$(call log_message,[INFO] gRPC Compilation complete!)

grpc-server-start:
	$(call log_message,[INFO] Starting gRPC server ...)
	@$(PYTHON) -u grpc_server.py
	$(call log_message,[INFO] gRPC server started successfully.)

grpc-internal-server-start:
	$(call log_message,[INFO] Starting gRPC internal server ...)
	@$(PYTHON) -u grpc_internal_server.py
	$(call log_message,[INFO] gRPC internal server started successfully.)

download-platforms:
	$(call log_message,[INFO] Downloading platforms JSON file ...)
	@curl -sSL -o platforms.json "$(SUPPORTED_PLATFORMS_URL)"
	$(call log_message,[INFO] Platforms JSON file downloaded successfully.)

create-dummy-user:
	$(call log_message,[INFO] Creating dummy user ...)
	@$(PYTHON) -m scripts.cli create -n +237123456789
	$(call log_message,[INFO] Dummy user created successfully.)

generate-static-keys:
	$(call log_message,[INFO] Generating x25519 static keys ...)
	@$(PYTHON) -m scripts.x25519_keygen generate -n 255 -v v1 && \
	$(PYTHON) -m scripts.x25519_keygen export --skip-if-exists
	$(call log_message,[INFO] x25519 static keys generated successfully.)

build-setup: grpc-compile download-platforms
runtime-setup: create-dummy-user generate-static-keys

clean:
	$(call log_message,[INFO] Cleaning build, environment, and generated files ...)
	@rm -f vault_pb2*
	@rm -f vault.db
	@rm -f hashing.key
	@rm -f encryption.key
	@rm -f platforms.json
	@rm -f .env
	@rm -rf venv/
	@rm -rf keystore/
	$(call log_message,[INFO] Clean complete.)
