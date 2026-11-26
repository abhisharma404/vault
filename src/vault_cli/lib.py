"""Shared path resolution.

All filesystem locations are derived from the location of this source file so
the program no longer depends on the current working directory.
"""

import os

# This file lives at <repo>/src/vault_cli/lib.py
SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO_ROOT = os.path.dirname(SRC_DIR)
PAYLOADS_DIR = os.path.join(SRC_DIR, 'payloads')
LOG_DIR = os.environ.get('VAULT_LOG_DIR') or os.path.join(REPO_ROOT, 'log')


def payload_path(name):
    """Absolute path to a payload file under ``src/payloads``."""
    return os.path.join(PAYLOADS_DIR, name)
