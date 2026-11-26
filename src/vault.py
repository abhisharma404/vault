#!/usr/bin/env python

"""Vault entrypoint.

This is a thin launcher; all parsing and dispatch live in
``vault_cli.cli``.
"""

from vault_cli.cli import main

if __name__ == '__main__':
    main()
