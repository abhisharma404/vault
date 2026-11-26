"""Compatibility shim.

Console helpers now live in ``vault_cli.colors``; this module remains so that
existing ``import colors`` calls in ``lib/`` keep working.
"""

from vault_cli.colors import *  # noqa: F401,F403
