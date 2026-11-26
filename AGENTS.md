# AGENTS.md

## Project

Vault is a Python 3 CLI security scanner ("Swiss army knife for hackers"). The
only entrypoint is `src/vault.py`; feature code lives under
`src/lib/{attacks,scanner,others,utilities,website_scanner,crawler}`. There is
no package metadata, test suite, CI, build system, or lint/format config.

CLI options are defined in `argparse` and dispatched by the sequential
`if args.<flag>:` block at the bottom of `src/vault.py`. Adding a feature means
touching the parser, the dispatcher, and a module under `src/lib/`.

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

## CLI / installer

- `./install.sh` writes a `vault` launcher to `~/.local/bin` (default; use
  `--prefix DIR` or `VAULT_PREFIX` to change it). The launcher runs the
  VaultENV python against `src/vault.py` and `cd`s into `src/` first, so the
  command works from any directory.
- Re-run `./install.sh` after moving the repo (paths are baked in).
  `./install.sh --uninstall` removes it. Overrides: `--name`, `--prefix`,
  `--python` (or `VAULT_NAME` / `VAULT_PREFIX` / `VAULT_PYTHON`).
- After installing, `vault -h` from anywhere is equivalent to
  `cd src && .../bin/python vault.py -h`.

## Run and verify

Run from `src/` (or via the installed `vault` command, which does this for you):

```sh
cd src
/opt/anaconda3/envs/VaultENV/bin/python vault.py -u http://127.0.0.1:8000/
```

Many modules resolve payloads as `os.getcwd() + '/payloads/...'` and write
`vault.log` to the current directory, so running from the repo root breaks
them.

There are no automated tests. Verify changes with:

```sh
# Syntax check (warnings are meaningful; keep compileall clean)
cd src && /opt/anaconda3/envs/VaultENV/bin/python -m compileall -q .

# Import sweep over src/lib. Expected exception: lib.website_scanner.xss.xss
# raises ModuleNotFoundError: No module named 'scanner' on direct import;
# vault.py injects that sibling directory into sys.path at runtime.
```

For behavioural smoke tests, serve a local page with `python -m http.server`
and exercise non-privileged features: `-info`, `-comment`, `-email`, `-fuzz`,
`-admin`, `-orv`, `-detect_cms`, `-jquery`, `-xss -this`, `-lfi`, and
`-hash -md5 -dir <tmpdir>`.

Raw-socket and nmap features (`-fin`, `-null`, `-ack`, `-xmas`, `-os_scan`,
attacks) require root and often fail in sandboxed/macOS environments; do not
use them as automated checks. Commands that hit third-party services (`-ssl`
SSL Labs, `-honey` Shodan, `-d` Google dork, jQuery CVE lookup) are
network-dependent and flaky.
