# Pitfalls

- **Run from `src/`** or use the installed `vault` launcher. The launcher `cd`s
  into `src/`; running `python src/vault.py` from the repo root is fine for the
  new layered code, but keep payload resolution via `vault_cli.lib` so it does
  not depend on cwd.
- **Dependency pins**: `requests==2.20.1` and `scapy==2.4.0` are broken on
  Python 3.15 (vendored `six.moves`). Requirements are already modernized; do
  not downgrade.
- **Root-only features**: raw-socket scans (`-fin`, `-null`, `-ack`, `-xmas`,
  `-os_scan`) and attacks require root and often fail on macOS/sandboxes.
- **Third-party services** (`-ssl` SSL Labs, `-honey` Shodan, `-d` Google dork,
  jQuery CVE feed) are network-dependent and can be rate-limited, blocked, or
  return non-JSON; these paths now fail gracefully rather than crashing.
- **SSL Labs rejects IP addresses** and some hostnames ("blacklisted"); the
  scanner surfaces a clear message instead of a `KeyError`.
- **Leftover `src/.vault_cli_root_bak/`**: a root-owned duplicate directory
  created during development. It is gitignored; remove it with
  `sudo rm -rf src/.vault_cli_root_bak`.
