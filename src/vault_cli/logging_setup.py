"""Per-session error logging.

Only ERROR-level records are written to disk. The log file is created lazily on
the first error of a session, under ``<repo>/log``, using a unique
``vault-error-<timestamp>-<pid>.log`` name so concurrent sessions never
overwrite each other.
"""

import logging
import os
import platform
import sys
import threading
import time

from vault_cli import lib


class SessionErrorHandler(logging.Handler):
    """Write ERROR records to a per-session file created on first error."""

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self._lock = threading.Lock()
        self._stream = None
        self._path = None

    @property
    def path(self):
        return self._path

    def _ensure_file(self):
        if self._stream is not None:
            return
        os.makedirs(lib.LOG_DIR, exist_ok=True)
        stamp = time.strftime('%Y%m%d-%H%M%S')
        filename = 'vault-error-{}-{}.log'.format(stamp, os.getpid())
        self._path = os.path.join(lib.LOG_DIR, filename)
        self._stream = open(self._path, 'a', encoding='utf-8')
        self._stream.write('=== Vault session {} (pid {}) ===\n'.format(
            time.strftime('%Y-%m-%dT%H:%M:%S'), os.getpid()))
        self._stream.write('python: {}  platform: {}\n'.format(
            platform.python_version(), platform.platform()))
        self._stream.write('cwd: {}\n'.format(os.getcwd()))
        self._stream.write('argv: {}\n'.format(' '.join(sys.argv)))
        self._stream.write('\n')

    def emit(self, record):
        try:
            with self._lock:
                self._ensure_file()
                # self.format() already appends the traceback when
                # record.exc_info is set (standard Formatter behaviour).
                self._stream.write(self.format(record) + '\n')
                self._stream.flush()
        except Exception:
            self.handleError(record)

    def close(self):
        with self._lock:
            if self._stream is not None:
                self._stream.close()
                self._stream = None
        super().close()


def configure_session_logging():
    """Configure (once) the ``vault`` logger with the session error handler."""
    logger = logging.getLogger('vault')
    if logger.handlers:
        return logger

    logger.setLevel(logging.ERROR)
    logger.propagate = False

    handler = SessionErrorHandler()
    formatter = logging.Formatter(
        fmt='%(asctime)s %(levelname)s %(name)s:%(funcName)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
