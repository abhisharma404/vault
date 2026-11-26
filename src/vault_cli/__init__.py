"""Vault CLI layered package.

Layers:
    cli.py           - argument parsing and flag -> handler dispatch
    config.py        - application constants and logger wiring
    lib.py           - shared path resolution (payloads, log directory)
    errors.py        - centralized error reporting (console + session log)
    logging_setup.py - per-session error log handler
    colors.py        - console output helpers
    validation.py    - input validation helpers
    features/        - one module per feature group
"""
