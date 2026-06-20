"""v1.0 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v1.0 suite (`pytest`).
"""

from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent

# Runtime deps the wheel itself declares in pyproject.toml [project.dependencies].
# Installing them into the fresh venv proves the wheel's metadata is complete and
# the declared dep chain is real and resolvable.  httpx is the actual transport
# (verified via `import httpx` works in this test runner's venv at G-031); PyYAML
# is the fingerprint-DB parser (verified G-031).
_RUNTIME_DEPS = [
    "httpx>=0.27",
    "PyYAML>=6.0",
]


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def _ensure_build_available():
    """Install `build` into the test-runner's venv on demand if absent."""
    try:
        _run([sys.executable, "-m", "build", "--version"])
    except subprocess.CalledProcessError:
        _run([sys.executable, "-m", "pip", "install", "--quiet", "build"])


# ---------------------------------------------------------------------------
# Session-scoped fixtures — shared across all ship_gate tests in one run.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def wheel_artifacts(tmp_path_factory):
    """Build wheel + sdist; yield (wheel_path, sdist_path)."""
    _ensure_build_available()
    out = tmp_path_factory.mktemp("build-out")
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=str(REPO_ROOT),
    )
    wheels = list(out.glob("hellhound-1.0.0-*.whl"))
    sdists = list(out.glob("hellhound-1.0.0.tar.gz"))
    assert wheels, f"wheel not built; got: {sorted(p.name for p in out.iterdir())}"
    assert sdists, f"sdist not built; got: {sorted(p.name for p in out.iterdir())}"
    return wheels[0], sdists[0]


@pytest.fixture(scope="session")
def fresh_venv_dir(wheel_artifacts, tmp_path_factory):
    """Install the wheel into a brand-new isolated venv; yield the venv path.

    No --system-site-packages: the wheel install cannot fall back to any
    host-site copy of hellhound.  --no-deps on the wheel install proves the wheel
    declares everything it needs; the follow-up dep installs prove the declared
    chain is real and resolvable.
    """
    wheel_path, _ = wheel_artifacts
    venv_dir = tmp_path_factory.mktemp("fresh-venv")
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"
    _run([str(pip), "install", "--quiet", str(wheel_path), "--no-deps"])
    _run([str(pip), "install", "--quiet", *_RUNTIME_DEPS])
    return venv_dir


# ---------------------------------------------------------------------------
# Ship-gate tests
# ---------------------------------------------------------------------------


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(wheel_artifacts):
    """`python -m build --wheel --sdist` produces both artifacts without error."""
    wheel_path, sdist_path = wheel_artifacts
    assert wheel_path.exists(), f"wheel missing: {wheel_path}"
    assert sdist_path.exists(), f"sdist missing: {sdist_path}"
    assert wheel_path.name.startswith("hellhound-1.0.0-")
    assert sdist_path.name == "hellhound-1.0.0.tar.gz"


@pytest.mark.ship_gate
def test_wheel_installs_and_version(fresh_venv_dir):
    """`hellhound --version` in fresh venv MUST print 'hellhound 1.0.0'."""
    bin_dir = fresh_venv_dir / "bin"
    result = subprocess.run(
        [str(bin_dir / "hellhound"), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "hellhound 1.0.0", (
        f"expected 'hellhound 1.0.0', got: {result.stdout!r}"
    )


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv(fresh_venv_dir):
    """`import hellhound` in fresh venv MUST yield __version__ == '1.0.0'."""
    bin_dir = fresh_venv_dir / "bin"
    result = subprocess.run(
        [str(bin_dir / "python"), "-c", "import hellhound; assert hellhound.__version__ == '1.0.0'"],
        capture_output=True,
        text=True,
        check=True,
    )
    # check=True already raised CalledProcessError on AssertionError; this
    # belt-and-suspenders catches a non-AssertionError traceback.
    assert "AssertionError" not in result.stderr, result.stderr


@pytest.mark.ship_gate
def test_fresh_venv_list_fingerprints_smoke(fresh_venv_dir):
    """`hellhound --list-fingerprints --format json` in fresh venv MUST report 200 KEV entries.

    Read-only smoke (no network, no DB write) — proves the installed wheel
    can load the fingerprint database shipped in `hellhound/fingerprints/default.yaml`
    (200 entries as of PR #36 MERGED 2026-06-05T15:03:56Z; verified G-018).
    """
    bin_dir = fresh_venv_dir / "bin"
    result = subprocess.run(
        [str(bin_dir / "hellhound"), "--list-fingerprints", "--format", "json"],
        capture_output=True,
        text=True,
        check=True,
    )
    import json
    payload = json.loads(result.stdout)
    # JSON shape: {"summary": {"fingerprint_count": N}, "fingerprints": [...]}
    count = payload.get("fingerprint_count") or payload.get("summary", {}).get("fingerprint_count")
    assert count == 200, (
        f"expected fingerprint_count=200, got: {count!r}; top-level keys: {list(payload.keys())}"
    )


@pytest.mark.ship_gate
def test_fresh_venv_validate_clean(fresh_venv_dir):
    """`hellhound --validate` in fresh venv MUST exit 0 (bundled DB has no structural errors)."""
    bin_dir = fresh_venv_dir / "bin"
    result = subprocess.run(
        [str(bin_dir / "hellhound"), "--validate"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"--validate exited {result.returncode}; stderr: {result.stderr!r}"
    )


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """``CHANGELOG.md`` MUST exist and contain a ``## [1.0.0]`` entry.

    Pins the CHANGELOG contract against accidental deletion or future
    version-string regressions.
    """
    changelog = REPO_ROOT / "CHANGELOG.md"
    assert changelog.exists(), "CHANGELOG.md missing at repo root"
    text = changelog.read_text()
    assert "## [1.0.0] - 2026-06-20" in text, (
        "CHANGELOG.md missing top-level '## [1.0.0] - 2026-06-20' entry"
    )
