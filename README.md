# Secure ledger security pipeline

This Python 3.11 Flask API uses SQLite and pip. CI installs the pinned direct
and transitive dependencies from `requirements.lock` and runs:

```sh
python -m pip install -r requirements.lock
python scripts/security_pipeline.py
```

Set `APP_TOKEN_SIGNING_KEY` to a secret of at least 32 bytes before starting
the application. Tests use an isolated database and a dummy signing key.
Bearer tokens cross the authentication boundary; users may transfer funds
only from their own accounts and cancel only their own pending orders. The
custom tests exercise those ownership and state rules through the API.

The pipeline runs pytest, Bandit SAST, pip-audit dependency scanning and
detect-secrets. SAST findings of medium or high severity with medium or high
confidence block; lower severity or confidence findings warn. All known
dependency vulnerabilities, secret findings, scanner errors and failed tests
block. pip-audit does not consistently supply severity, so it blocks even
unrated vulnerabilities. Secret verification is disabled to avoid sending
potential credentials to external services.

The pipeline also scans temporary fixtures: an insecure TLS request must
trigger blocking Bandit rule B501, and a low-severity assertion must warn
without failing. The fixtures are deleted and the secure baseline is checked
again. GitHub Actions retains the machine-readable reports as an artifact.
