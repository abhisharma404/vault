"""Compatibility shim.

Logging now lives in ``vault_cli.logging_setup``; this module remains so any
legacy ``import logger`` keeps working.
"""

from vault_cli.logging_setup import configure_session_logging  # noqa: F401


class Logger:
    """Backward-compatible wrapper around the session logger setup."""

    @staticmethod
    def create_logger(debug_filename=None, logger_name="vault"):
        return configure_session_logging()
