# SPDX-License-Identifier: GPL-3.0-only
"""Reset Password gRPC service implementation"""

from base_logger import get_logger

logger = get_logger(__name__)


def ResetPassword(self, request, context):
    """Handles resetting an entity's password."""
