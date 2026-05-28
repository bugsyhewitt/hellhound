"""Tests for external fingerprint directory support (--fingerprint-dir).

POST_V01 item 9: power users supply a custom fingerprint set in their own
directory. Custom entries override bundled ones by id; new entries are
appended; bundled-only entries are preserved.
"""

from pathlib import Path

import pytest

from hellhound.cli import build_parser, main
from hellhound.fingerprint import (
    Fingerprint,
    load_fingerprint_set,
    load_fingerprint_set_with_dir,
    merge_fingerprints,
)

CUSTOM_YAML = """\
fingerprints:
  - id: acme-secret-cam
    vendor: Acme
    model_class: Proprietary IP Camera
    severity: high
    match:
      http_title: AcmeCam
    default_credentials:
      - {username: admin, password: acme}
    auth:
      type: basic
      path: /login
"""

# Override an id that exists in the bundled default set.
OVERRIDE_YAML = """\
fingerprints:
  - id: hikvision-dvr
    vendor: Hikvision
    model_class: OVERRIDDEN MODEL
    severity: low
    match:
      http_title: Hikvision
    default_credentials:
      - {username: root, password: custompass}
    auth:
      type: basic
      path: /custom
"""


def _write_set(directory: Path, name: str, body: str) -> Path:
    path = directory / f"{name}.yaml"
    path.write_text(body, encoding="utf-8")
    return path


# ---- merge_fingerprints unit tests -----------------------------------------


def _fp(fid: str, vendor: str = "V", model: str = "M") -> Fingerprint:
    from hellhound.fingerprint import AuthCheck, Credential, MatchCriteria

    return Fingerprint(
        id=fid,
        vendor=vendor,
        model_class=model,
        severity="medium",
        match=MatchCriteria(http_title="x"),
        credentials=[Credential("admin", "admin")],
        auth=AuthCheck(),
    )


def test_merge_appends_new_entries():
    bundled = [_fp("a"), _fp("b")]
    overrides = [_fp("c")]
    merged = merge_fingerprints(bundled, overrides)
    assert [f.id for f in merged] == ["a", "b", "c"]


def test_merge_overrides_by_id_in_place():
    bundled = [_fp("a", vendor="Bundled"), _fp("b")]
    overrides = [_fp("a", vendor="Custom")]
    merged = merge_fingerprints(bundled, overrides)
    assert [f.id for f in merged] == ["a", "b"]  # no duplicate, order kept
    a = next(f for f in merged if f.id == "a")
    assert a.vendor == "Custom"


def test_merge_preserves_bundled_only_entries():
    bundled = [_fp("a"), _fp("b")]
    merged = merge_fingerprints(bundled, [])
    assert [f.id for f in merged] == ["a", "b"]


def test_merge_combines_override_and_append():
    bundled = [_fp("a", vendor="Bundled"), _fp("b")]
    overrides = [_fp("a", vendor="Custom"), _fp("z")]
    merged = merge_fingerprints(bundled, overrides)
    assert [f.id for f in merged] == ["a", "b", "z"]
    assert next(f for f in merged if f.id == "a").vendor == "Custom"


# ---- load_fingerprint_set_with_dir tests -----------------------------------


def test_load_with_no_dir_returns_bundled():
    bundled = load_fingerprint_set("default")
    got = load_fingerprint_set_with_dir("default", fingerprint_dir=None)
    assert [f.id for f in got] == [f.id for f in bundled]


def test_load_with_custom_dir_picks_up_new_entry(tmp_path):
    _write_set(tmp_path, "default", CUSTOM_YAML)
    bundled = load_fingerprint_set("default")
    got = load_fingerprint_set_with_dir("default", fingerprint_dir=tmp_path)

    ids = {f.id for f in got}
    # custom entry present
    assert "acme-secret-cam" in ids
    # bundled entries still present
    bundled_ids = {f.id for f in bundled}
    assert bundled_ids <= ids
    assert len(got) == len(bundled) + 1


def test_load_with_custom_dir_overrides_bundled_by_id(tmp_path):
    _write_set(tmp_path, "default", OVERRIDE_YAML)
    bundled = load_fingerprint_set("default")
    got = load_fingerprint_set_with_dir("default", fingerprint_dir=tmp_path)

    # no new entry added (same id overridden in place)
    assert len(got) == len(bundled)
    hik = next(f for f in got if f.id == "hikvision-dvr")
    assert hik.model_class == "OVERRIDDEN MODEL"
    assert hik.credentials[0].password == "custompass"


def test_load_with_missing_dir_raises(tmp_path):
    missing = tmp_path / "does-not-exist"
    with pytest.raises(FileNotFoundError):
        load_fingerprint_set_with_dir("default", fingerprint_dir=missing)


def test_load_with_dir_lacking_named_set_raises(tmp_path):
    # directory exists but has no default.yaml
    with pytest.raises(FileNotFoundError):
        load_fingerprint_set_with_dir("default", fingerprint_dir=tmp_path)


# ---- CLI wiring tests ------------------------------------------------------


def test_cli_parses_fingerprint_dir_flag():
    parser = build_parser()
    args = parser.parse_args(
        ["--target", "192.0.2.1", "--fingerprint-dir", "/tmp/fp"]
    )
    assert args.fingerprint_dir == "/tmp/fp"


def test_cli_fingerprint_dir_defaults_to_none():
    parser = build_parser()
    args = parser.parse_args(["--target", "192.0.2.1"])
    assert args.fingerprint_dir is None


def test_cli_bad_fingerprint_dir_errors_cleanly(tmp_path, capsys):
    # tmp_path has no default.yaml -> main should exit 2 with an error message,
    # never reaching the scan.
    rc = main(["--target", "192.0.2.1", "--fingerprint-dir", str(tmp_path)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "fingerprint set" in err.lower()
