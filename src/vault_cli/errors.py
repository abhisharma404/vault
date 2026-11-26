"""Centralized error reporting.

Every genuine failure should go through :func:`report_error` so it is both
printed to the console and written to the per-session error log (ERROR level
only). Warnings are handled separately by ``colors.warning`` and are never
written to the log.
"""

import logging

LOGGER = logging.getLogger('vault')


def get_logger():
    return LOGGER


def report_error(message, exc=None):
    """Print ``message`` and record it in the session error log.

    When ``exc`` is an exception object, its traceback is captured in the log.
    """
    from vault_cli import colors

    message = str(message)
    colors.error(message)

    if exc is not None and isinstance(exc, BaseException):
        LOGGER.error(message, exc_info=(type(exc), exc, exc.__traceback__))
    else:
        LOGGER.error(message)
