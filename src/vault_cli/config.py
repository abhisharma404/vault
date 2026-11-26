"""Application configuration and one-time setup."""

from vault_cli import logging_setup

VERSION = '1.0.0'

BANNER = r""" ____   _________   ____ ___.____  ___________
\   \ /   /  _  \ |    |   \    | \__    ___/
 \   Y   /  /_\  \|    |   /    |   |    |
  \     /    |    \    |  /|    |___|    |
   \___/\____|__  /______/ |_______ \____|
                \/                 \/         """


def setup_logging():
    """Configure session error logging and return the ``vault`` logger."""
    return logging_setup.configure_session_logging()
