# Testing / verification

There is no automated test suite. Verify changes with:

```sh
# Syntax check (keep it warning-free)
cd src && /opt/anaconda3/envs/VaultENV/bin/python -m compileall -q .

# Import sweep over src/lib and src/vault_cli
cd src && /opt/anaconda3/envs/VaultENV/bin/python - <<'PY'
import importlib, os
for root, dirs, files in os.walk('.'):
    if '__pycache__' in root: continue
    for f in files:
        if f.endswith('.py') and f != '__init__.py':
            m = os.path.join(root, f)[:-3].replace(os.sep, '.')
            try: importlib.import_module(m)
            except Exception as e: print('FAIL', m, e)
PY
```

Behavioural smoke test: serve a page and exercise non-privileged features:

```sh
python -m http.server 8000 --directory /tmp/site &
vault -u http://127.0.0.1:8000/ -info
vault -u http://127.0.0.1:8000/ -comment
vault -u http://127.0.0.1:8000/ -email
vault -u http://127.0.0.1:8000/ -fuzz
vault -u http://127.0.0.1:8000/ -detect_cms
vault -u http://127.0.0.1:8000/ -jquery
vault -u http://127.0.0.1:8000/ -xss -this
vault -u http://127.0.0.1:8000/ -lfi
vault -u http://127.0.0.1:8000/ -admin
vault -u http://127.0.0.1:8000/ -orv
```

Logging checks:

- A session with no errors must not create any file in `<repo>/log/`.
- A session with an error (e.g. `vault -ssl -u 127.0.0.1`) must create exactly
  one `log/vault-error-<timestamp>-<pid>.log` containing a header, the error
  message, and a traceback.
- Warnings appear on the console (`[~]`) but never in the log.
