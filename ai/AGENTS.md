# AGENTS.md — Vault

## Project

Vault is a Python 3 CLI security scanner ("Swiss army knife for hackers").
The entrypoint is `src/vault.py` (a thin launcher). The CLI and feature
handlers live in `src/vault_cli/`; the low-level implementations live in
`src/lib/`. There is no package metadata, test suite, CI, build system, or
lint/format config.

## Layered structure (`src/`)

- `vault.py` — thin entrypoint: `from vault_cli.cli import main`.
- `vault_cli/cli.py` — `argparse` parser and flag → handler dispatch.
- `vault_cli/config.py` — banner and logger wiring.
- `vault_cli/lib.py` — path resolution (`PAYLOADS_DIR`, `LOG_DIR`,
  `payload_path()`). Never use `os.getcwd()` for resources.
- `vault_cli/errors.py` — `report_error(message, exc=None)` (prints + logs).
- `vault_cli/logging_setup.py` — `SessionErrorHandler` (ERROR-only,
  per-session file).
- `vault_cli/colors.py` — `error` / `success` / `info` / `warning`.
- `vault_cli/validation.py` — URL/IP/range/root checks + SIGINT handler.
- `vault_cli/features/` — one module per feature group: `attacks`, `scanners`,
  `web`, `others`, `crawler`, `utilities`.
- `lib/` — low-level implementation packages (kept as-is).
- `payloads/` — data files.
- `colors.py`, `logger.py` — compatibility shims for `lib/` modules that still
  `import colors` / `import logger`.

## Environment

- Use the existing conda environment `VaultENV`:
  `/opt/anaconda3/envs/VaultENV/bin/python` (Python 3.15.2).
- Refresh dependencies with
  `/opt/anaconda3/envs/VaultENV/bin/pip install -r requirements.txt`.
- Keep `requirements.txt` modern. The old `bs4`/`HTMLParser` packages and the
  old `requests==2.20.1` / `scapy==2.4.0` pins fail on Python 3.15 with
  `No module named 'urllib3.packages.six.moves'` or
  `scapy.modules.six.moves`. Do not downgrade them.
- OS scan (`-os_scan`) needs the external `nmap` binary on `PATH`.
- The keylogger (`-keylogger`, via `pynput`) needs macOS Accessibility
  permission and will not run unattended.

## Logging and error handling

- Only ERROR-level records are logged. Warnings are console-only.
- Logs are written to `<repo>/log/`, one `vault-error-<timestamp>-<pid>.log`
  per session, created lazily on the first error (session header + traceback).
  A session with no errors creates no file.
- Report failures through `errors.report_error(message, exc=...)`. Use
  `colors.warning(...)` for non-fatal conditions (never logged).

## CLI / installer

- `./install.sh` writes a `vault` launcher to `~/.local/bin` (default; use
  `--prefix DIR` or `VAULT_PREFIX` to change it). The launcher runs the
  VaultENV python against `src/vault.py` and `cd`s into `src/` first, so the
  command works from any directory.
- Re-run `./install.sh` after moving the repo (paths are baked in).
  `./install.sh --uninstall` removes it. Overrides: `--name`, `--prefix`,
  `--python` (or `VAULT_NAME` / `VAULT_PREFIX` / `VAULT_PYTHON`).

## Run and verify

Run from `src/` (or via the installed `vault` command, which does this for you):

```sh
cd src
/opt/anaconda3/envs/VaultENV/bin/python vault.py -u http://127.0.0.1:8000/
```

There are no automated tests. See `ai/testing.md` for the verification
commands. See `ai/pitfalls.md` for known gotchas.
