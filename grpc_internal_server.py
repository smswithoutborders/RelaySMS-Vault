"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import os
from concurrent import futures

import grpc
from grpc_interceptor import ServerInterceptor
import vault_pb2_grpc

from src.utils import get_configs
from src.grpc_entity_internal_service import EntityInternalService
from base_logger import get_logger

logger = get_logger("vault.grpc.internal.server")


class LoggingInterceptor(ServerInterceptor):
    """
    gRPC server interceptor for logging requests.
    """

    def __init__(self):
        """
        Initialize the LoggingInterceptor.
        """
        self.logger = logger
        self.server_protocol = "HTTP/2.0"

    def intercept(self, method, request_or_iterator, context, method_name):
        """
        Intercept method calls for each incoming RPC.
        """
        response = method(request_or_iterator, context)
        if context.details():
            self.logger.error(
                "%s %s - %s -",
                method_name,
                self.server_protocol,
                str(context.code()).split(".")[1],
            )
        else:
            self.logger.info("%s %s - %s -", method_name, self.server_protocol, "OK")
        return response


def serve():
    """
    Starts the gRPC internal server and listens for requests.
    """
    mode = get_configs("MODE", default_value="development")
    hostname = get_configs("GRPC_HOST")

    num_cpu_cores = os.cpu_count()
    max_workers = 10

    logger.info("Starting server in %s mode...", mode)
    logger.info("Hostname: %s", hostname)
    logger.info("Logical CPU cores available: %s", num_cpu_cores)
    logger.info("gRPC server max workers: %s", max_workers)

    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        interceptors=[LoggingInterceptor()],
    )
    vault_pb2_grpc.add_EntityInternalServicer_to_server(EntityInternalService(), server)

    if mode == "production":
        server_certificate = get_configs("SSL_CERTIFICATE")
        private_key = get_configs("SSL_KEY")
        secure_port = get_configs("GRPC_INTERNAL_SSL_PORT")

        logger.info("Secure port: %s", secure_port)
        try:
            with open(server_certificate, "rb") as f:
                server_certificate_data = f.read()
            with open(private_key, "rb") as f:
                private_key_data = f.read()

            server_credentials = grpc.ssl_server_credentials(
                ((private_key_data, server_certificate_data),)
            )
            server.add_secure_port(f"{hostname}:{secure_port}", server_credentials)
            logger.info(
                "TLS is enabled: The server is securely running at %s:%s",
                hostname,
                secure_port,
            )
        except FileNotFoundError as e:
            logger.critical(
                (
                    "Unable to start server: TLS certificate or key file not found: %s. "
                    "Please check your configuration."
                ),
                e,
            )
            raise
        except Exception as e:
            logger.critical(
                (
                    "Unable to start server: Error loading TLS credentials: %s. ",
                    "Please check your configuration.",
                ),
                e,
            )
            raise
    else:
        port = get_configs("GRPC_INTERNAL_PORT")
        logger.info("Insecure port: %s", port)

        server.add_insecure_port(f"{hostname}:{port}")
        logger.warning(
            "The server is running in insecure mode at %s:%s", hostname, port
        )

    server.start()

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down the server...")
        server.stop(0)
        logger.info("The server has stopped successfully")


if __name__ == "__main__":
    serve()
