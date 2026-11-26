"""Centralized error handling and reporting.

Every genuine failure should go through :func:`report_error` so it is both
printed to the console and written to the per-session error log (ERROR level
only). Warnings are handled separately by ``colors.warning`` and are never
written to the log.

Structured exceptions (:class:`VaultError` and its subclasses) carry a stable
error ``code`` chosen from the table below, the user-facing ``message``, an
optional ``hint`` and the original exception as ``orig_exc``. Call sites pick
the code that best matches the failure.

Error code table
----------------
E1001 invalid IP address
E1002 invalid IP range
E1003 URL required
E1004 IP required
E1005 root privileges required
E1006 no action specified
E1007 start/end IP range both required
E2001 request failed
E2002 request timed out
E2003 DNS/connection failure
E3001 scan failed
E3002 scan produced no results
E4001 external service error
E4002 external service rate-limited/blocked
E5001 insufficient privileges (root)
E6001 module/import failed
E6002 payload/resource file missing
E6003 log directory unavailable
"""

import logging
import traceback

from vault_cli import colors

LOGGER = logging.getLogger('vault')

# Module-level verbosity state, updated via set_verbosity().
VERBOSE = False
DEBUG = False


class VaultError(Exception):
    """Base class for structured Vault errors.

    Attributes:
        code (str): stable machine-readable error code (default ``E0000``).
        message (str): user-facing error message.
        hint (str|None): optional follow-up hint; resolved lazily from
            ``vault_cli.hints.hint_for`` when not passed explicitly.
        orig_exc (BaseException|None): the original exception, if any.
    """

    code = 'E0000'

    def __init__(self, message, *, hint=None, exc=None):
        self.message = str(message)
        self.orig_exc = exc
        if hint is None:
            hint = self._lookup_hint()
        self.hint = hint
        super().__init__(self.message)

    def _lookup_hint(self):
        # Imported lazily to avoid circular imports; any failure (missing
        # module, lookup error, ...) simply leaves the hint as None.
        try:
            from vault_cli import hints
            return hints.hint_for(self)
        except Exception:
            return None


class UsageError(VaultError):
    """Invalid CLI usage / arguments."""

    code = 'E1000'


class ValidationError(UsageError):
    """Invalid input value (IP, URL, range, ...)."""

    code = 'E1100'


class NetworkError(VaultError):
    """Network/request-level failure."""

    code = 'E2000'


class ScanError(VaultError):
    """A scan run failed or produced no usable results."""

    code = 'E3000'


class ExternalServiceError(VaultError):
    """A third-party service failed or blocked the request."""

    code = 'E4000'


class PrivilegeError(VaultError):
    """Insufficient privileges for the requested feature."""

    code = 'E5000'


class ConfigError(VaultError):
    """Configuration, import, payload or log-directory failure."""

    code = 'E6000'


def _resolve_hint(hint, exc):
    """Resolve the hint to show, in order of precedence."""
    if hint is not None:
        return hint
    if exc is not None and isinstance(exc, VaultError) and exc.hint is not None:
        return exc.hint
    if exc is not None:
        try:
            from vault_cli import hints
            return hints.hint_for(exc)
        except Exception:
            return None
    return None


def report_error(message, exc=None, *, code=None, hint=None):
    """Print ``message`` and record it in the session error log.

    Args:
        message: user-facing error text.
        exc: optional exception that caused the failure. When it is a
            :class:`VaultError`, its ``code``/``hint`` are used as defaults.
        code: optional error code from the table above.
        hint: optional hint printed below the error.

    This function must never raise: console output and logging failures are
    swallowed so error reporting can not mask the original problem.
    """
    try:
        if exc is not None and isinstance(exc, VaultError):
            if code is None:
                code = exc.code
            if hint is None:
                hint = exc.hint

        hint = _resolve_hint(hint, exc)

        colors.error(str(message))

        if hint:
            print('    Hint: ' + str(hint))

        if VERBOSE and exc is not None:
            traceback.print_exception(type(exc), exc, exc.__traceback__)

        try:
            kwargs = {'extra': {'error_code': code, 'hint': hint}}
            if exc is not None and isinstance(exc, BaseException):
                kwargs['exc_info'] = (type(exc), exc, exc.__traceback__)
            LOGGER.error(str(message), **kwargs)
        except Exception:
            # Logging must never break error reporting.
            pass
    except Exception:
        # report_error must never raise.
        pass


def had_errors():
    """Return True if at least one error has been reported this session."""
    from vault_cli import logging_setup
    return logging_setup.had_errors()


def set_verbosity(verbose, debug):
    """Update the module-level VERBOSE/DEBUG flags."""
    global VERBOSE, DEBUG
    VERBOSE = bool(verbose)
    DEBUG = bool(debug)
