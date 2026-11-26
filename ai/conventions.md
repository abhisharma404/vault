# Conventions

## Layers and ownership

- `src/vault_cli/cli.py` owns argument parsing and dispatch. Add a new flag in
  `build_parser()` and dispatch it in `run()`.
- `src/vault_cli/features/` owns the thin feature handlers that wrap the
  low-level `lib/` modules. Put a new feature handler in the matching group
  module (`attacks`, `scanners`, `web`, `others`, `crawler`, `utilities`).
- `src/lib/` owns the actual implementation. Keep it independent of the CLI.

## Error handling

- Any genuine failure must go through `errors.report_error(message)` (or pass
  `exc=e` inside an `except` block to capture the traceback). Do not leave
  bare `print(e)` for failures — log them.
- Non-fatal, informational conditions use `colors.warning(...)`. Warnings are
  console-only and never written to the log.
- Benign scan outcomes (e.g. "No LFI detected") are not errors; use
  `colors.info`/`colors.success`.

## Paths

- Never use `os.getcwd()` to locate payloads or logs. Use
  `vault_cli.lib.payload_path(name)` (or `vault_cli.lib.PAYLOADS_DIR`,
  `vault_cli.lib.LOG_DIR`).

## Style

- Follow the surrounding code (the project predates modern tooling): no
  formatter/linter is configured, so match nearby formatting rather than
  applying a new style.
