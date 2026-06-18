# hellhound v0.1 — Acceptance Criteria

The criteria that define hellhound v0.1. Each is independently testable;
the `Ship-gate` block at the bottom is the single command sequence that
proves all six are met. The "current state" snapshot at the bottom is
refreshed each release.

## Criteria

### 1. Installable
hellhound installs cleanly on Python 3.13+ via `pip install -e .` or via
the built wheel, exposes the `hellhound` console script, and the package
`__version__` matches `pyproject.toml`'s declared version.

- `tests/test_smoke.py::test_package_imports_with_version`
- wheel smoke (manual / CI): `python -m build --wheel` then install in a
  fresh venv and assert `hellhound --version` and `python -c "import hellhound"`.

### 2. CLI surface
`build_parser()` exposes every documented option with the documented
defaults. The headline options (`--target`, `--ports`, `--fingerprint-set`,
`--format`, `--timeout`, `--concurrency`) are present and parseable.

- `tests/test_cli.py`
- per-flag test files for Phase-2 additions:
  `test_sarif.py`, `test_rate_limit.py`, `test_retries.py`,
  `test_exclusions.py`, `test_progress.py`, `test_exit_code.py`,
  `test_list_fingerprints.py`, `test_validate.py`.

### 3. Fingerprint DB minimum
The bundled `default` set contains at least 10 well-formed entries
(unique id, severity in {low, medium, high, critical}, auth in {basic, form},
match block with ≥ 1 positive condition, ≥ 1 default credential).

- `tests/test_fingerprints.py::test_database_meets_minimum_size`
- `tests/test_fingerprints.py::test_bundled_database_entries_are_well_formed`
- `tests/test_validate.py` (the `--validate` path also enforces this).

### 4. CLI end-to-end paths
A no-network mock-transport scan against the bundled DB produces
well-formed JSON / text / CSV / SARIF output for at least one real
fingerprint (headline: Hikvision).

- `tests/test_smoke.py::test_end_to_end_hikvision_detection_and_output`
- `tests/test_scanner.py` (criterion-5 end-to-end surface).

### 5. Headline detection works against a live device (bonus)
An optional Docker-gated integration test spins up a container
masquerading as a Hikvision DVR and confirms the live HTTP path matches
and authenticates with `admin:12345`. Auto-skipped when Docker is
absent; never blocks CI.

- `tests/integration/test_live_hikvision.py`.

### 6. Smoke gate
`pytest -m "not integration"` is all-green and `python -m build
--sdist --wheel` succeeds, producing `dist/hellhound-0.1.0-py3-none-any.whl`
and `dist/hellhound-0.1.0.tar.gz`.

## Ship-gate (single command sequence)

```bash
pytest -m "not integration"        # criteria 1–5
python -m build --sdist --wheel    # criterion 6
# install the wheel in a fresh venv and verify:
python -m venv /tmp/hh && /tmp/hh/bin/pip install -q dist/hellhound-0.1.0-py3-none-any.whl
/tmp/hh/bin/hellhound --version    # → "hellhound 0.1.0"
/tmp/hh/bin/python -c "import hellhound; assert hellhound.__version__ == '0.1.0'"
```

## Scope (v0.1) — in / out

In scope: HTTP/HTTPS fingerprinting and default-credential checking over a
CIDR range or single host, JSON/text/CSV/SARIF output (stdout or file), a
YAML fingerprint database, custom fingerprint directories, rate limiting,
retries, progress reporting, inventory mode, validation mode, exit-code
gating. See README § "Scope (v0.1)".

Out of scope (deliberately, see README and POST_V01.md): Telnet / SSH
scanning or brute-forcing, any active exploitation or post-auth action,
Shodan / Censys API integration, a web UI or persistent daemon mode,
firmware extraction, non-default credential wordlists / brute force,
agent / scheduled mode.

## Current state (snapshot at v0.1)

- Bundled fingerprint count: 200 (`default` set)
- Severity distribution: 131 critical / 60 high / 9 medium
- Fingerprints with `cve` field populated: 170
- `pytest -m "not integration"`: 424 passed, 1 skipped, 0 failed
- `python -m build --sdist --wheel`: produces wheel + sdist
- `hellhound --version`: `hellhound 0.1.0`
- `python -c "import hellhound; print(hellhound.__version__)"`: `0.1.0`
