"""Per-session error logging.

Only ERROR-level records are written to disk. Nothing is created until the
first error of a session; from then on two files share the stem
``vault-error-<YYYYmmdd>-<HHMMSS>-<pid>`` under ``vault_cli.lib.LOG_DIR``
(falling back to the system temp directory when the log directory cannot be
created):

- ``.log``   — human-readable: a session header plus one block per error.
- ``.jsonl`` — machine-readable sidecar: one JSON object per line (a session
  header object first, then one object per error).

All file access happens under a lock (the fuzzer and hash scanner use threads)
and ``emit`` never raises.
"""

import json
import logging
import os
import platform
import sys
import tempfile
import threading
import time
from typing import Optional

from vault_cli import colors
from vault_cli import lib

_handler = None


class SessionErrorHandler(logging.Handler):
    """Write ERROR records to a per-session ``.log`` / ``.jsonl`` pair.

    The files are created lazily on the first emitted error. The handler also
    acts as the JSONL sidecar writer, so both files share the same session
    stem, lock and lifecycle.

    Public attributes:
        errors_written: number of ERROR records emitted so far.
        current_path:   absolute path of the human-readable ``.log`` file, or
                        None until the first error creates it.
    """

    def __init__(self):
        super().__init__(level=logging.ERROR)
        self._lock = threading.RLock()
        self._log_stream = None
        self._jsonl_stream = None
        self._jsonl_path = None
        self._fallback_warned = False
        self.errors_written = 0
        self.current_path = None

    @property
    def path(self):
        """Backward-compatible alias for :attr:`current_path`."""
        return self.current_path

    def _stem(self):
        return 'vault-error-{}-{}'.format(
            time.strftime('%Y%m%d-%H%M%S'), os.getpid())

    def _session_data(self):
        return {
            'type': 'session',
            'time': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'pid': os.getpid(),
            'python': platform.python_version(),
            'platform': platform.platform(),
            'cwd': os.getcwd(),
            'argv': ' '.join(sys.argv),
        }

    def _ensure_files(self):
        if self._log_stream is not None:
            return
        stem = self._stem()
        for directory in (lib.LOG_DIR, tempfile.gettempdir()):
            log_stream = jsonl_stream = None
            try:
                os.makedirs(directory, exist_ok=True)
                log_stream = open(os.path.join(directory, stem + '.log'),
                                  'a', encoding='utf-8')
                jsonl_stream = open(os.path.join(directory, stem + '.jsonl'),
                                    'a', encoding='utf-8')
            except OSError:
                for stream in (log_stream, jsonl_stream):
                    if stream is not None:
                        try:
                            stream.close()
                        except Exception:
                            pass
                continue
            self._log_stream = log_stream
            self._jsonl_stream = jsonl_stream
            self.current_path = os.path.join(directory, stem + '.log')
            self._jsonl_path = os.path.join(directory, stem + '.jsonl')
            self._write_session_headers()
            return
        # Neither the log directory nor the temp directory could be used:
        # drop the write and warn (once) on the console.
        if not self._fallback_warned:
            self._fallback_warned = True
            colors.warning('Error logging unavailable: cannot write to {} or '
                           '{}; errors will not be saved'.format(
                               lib.LOG_DIR, tempfile.gettempdir()))

    def _write_session_headers(self):
        data = self._session_data()
        self._log_stream.write('=== Vault session {} (pid {}) ===\n'.format(
            data['time'], data['pid']))
        self._log_stream.write('python: {}  platform: {}\n'.format(
            data['python'], data['platform']))
        self._log_stream.write('cwd: {}\n'.format(data['cwd']))
        self._log_stream.write('argv: {}\n'.format(data['argv']))
        self._log_stream.flush()
        self._jsonl_stream.write(json.dumps(data, default=str) + '\n')
        self._jsonl_stream.flush()

    def _format_exception(self, record):
        formatter = self.formatter or logging.Formatter()
        return formatter.formatException(record.exc_info)

    def _format_block(self, record):
        message_record = record
        if record.exc_info:
            # self.format() appends the formatted traceback when exc_info is
            # set, so format a copy without it: the message line stays clean
            # and the traceback appears exactly once, on its own line.
            message_record = logging.makeLogRecord(record.__dict__)
            message_record.exc_info = None
            message_record.exc_text = None
        lines = [
            '=== Error #{} ==='.format(self.errors_written),
            'time: {}'.format(time.strftime('%Y-%m-%d %H:%M:%S',
                                            time.localtime(record.created))),
            'code: {}'.format(record.__dict__.get('error_code') or 'E0000'),
            'feature: {}'.format(record.funcName),
            'message: {}'.format(self.format(message_record)),
        ]
        hint = record.__dict__.get('hint')
        if hint:
            lines.append('hint: {}'.format(hint))
        if record.exc_info:
            lines.append('traceback: {}'.format(
                self._format_exception(record)))
        return '\n' + '\n'.join(lines) + '\n'

    def _format_jsonl(self, record):
        obj = {
            'type': 'error',
            'seq': self.errors_written,
            'time': time.strftime('%Y-%m-%dT%H:%M:%S',
                                  time.localtime(record.created)),
            'code': record.__dict__.get('error_code') or 'E0000',
            'feature': record.funcName,
            'level': record.levelname,
            'message': record.getMessage(),
        }
        hint = record.__dict__.get('hint')
        if hint:
            obj['hint'] = str(hint)
        if record.exc_info:
            obj['exc_type'] = record.exc_info[0].__name__
            obj['traceback'] = self._format_exception(record)
        return json.dumps(obj, default=str)

    def emit(self, record):
        try:
            with self._lock:
                self.errors_written += 1
                self._ensure_files()
                if self._log_stream is None:
                    return
                self._log_stream.write(self._format_block(record))
                self._log_stream.flush()
                self._jsonl_stream.write(self._format_jsonl(record) + '\n')
                self._jsonl_stream.flush()
        except Exception:
            self.handleError(record)

    def close(self):
        with self._lock:
            for name in ('_log_stream', '_jsonl_stream'):
                stream = getattr(self, name)
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass
                    setattr(self, name, None)
        super().close()


def configure_session_logging() -> logging.Logger:
    """Configure (once) the ``vault`` logger with the session error handler.

    Idempotent: subsequent calls return the already-configured logger.
    """
    global _handler
    logger = logging.getLogger('vault')
    if logger.handlers:
        return logger

    logger.setLevel(logging.ERROR)
    logger.propagate = False

    handler = SessionErrorHandler()
    handler.setFormatter(logging.Formatter(fmt='%(message)s'))
    logger.addHandler(handler)
    _handler = handler

    return logger


def had_errors() -> bool:
    """Return True once any ERROR record has been emitted in this process."""
    return _handler is not None and _handler.errors_written > 0


def get_current_path() -> Optional[str]:
    """Absolute path of the human-readable error log, or None.

    Returns None until the first error of the session creates the file.
    """
    if _handler is None:
        return None
    return _handler.current_path
