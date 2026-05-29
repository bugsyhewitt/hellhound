"""Tests for fingerprint database validation (--validate / validate_fingerprints).

The fingerprint database is hellhound's core product and has grown to dozens of
entries across many contributions. A typo or copy-paste slip silently degrades
the tool: an invalid severity corrupts the SARIF level mapping, a duplicate id
breaks --fingerprint-dir merging and SARIF rule deduplication, a fingerprint with
no positive match condition can never fire, and one with no default credentials
has nothing to check. None of these raise on their own.

These tests cover the pure ``validate_fingerprints`` checker (each rule in
isolation, error accumulation, and the clean bundled set), the validating load
paths and the ``FingerprintValidationError``, and the ``--validate`` CLI mode
(parser surface, clean exit 0, dirty exit 2, error reporting to stderr, the
post-merge custom-dir gate, and the no-network short-circuit).
"""

from __future__ import annotations

from unittest import mock

import pytest

from hellhound import cli
from hellhound.fingerprint import (
    AuthCheck,
    Credential,
    Fingerprint,
    FingerprintValidationError,
    MatchCriteria,
    load_fingerprint_set,
    load_fingerprint_set_with_dir,
    validate_fingerprints,
)


def _fp(
    id: str = "ok-fp",
    *,
    severity: str = "critical",
    auth_type: str = "basic",
    match: MatchCriteria | None = None,
    credentials: list[Credential] | None = None,
) -> Fingerprint:
    """A valid fingerprint by default; override one field to make it invalid."""
    return Fingerprint(
        id=id,
        vendor="Acme",
        model_class="IP Camera",
        severity=severity,
        match=match if match is not None else MatchCriteria(http_title="Acme"),
        credentials=credentials if credentials is not None else [Credential("admin", "admin")],
        auth=AuthCheck(type=auth_type, path="/login"),
    )


# --------------------------------------------------------------- validate_fingerprints


def test_valid_set_has_no_errors():
    assert validate_fingerprints([_fp("a"), _fp("b")]) == []


def test_bundled_default_set_is_valid():
    # The shipped database must always pass its own validation.
    fps = load_fingerprint_set("default")
    assert validate_fingerprints(fps) == []
    assert len(fps) >= 1


def test_duplicate_id_is_reported_once_with_count():
    errors = validate_fingerprints([_fp("dup"), _fp("dup"), _fp("dup")])
    dup_errors = [e for e in errors if "duplicate id" in e]
    assert len(dup_errors) == 1
    assert "'dup'" in dup_errors[0]
    assert "3 times" in dup_errors[0]


def test_invalid_severity_is_reported():
    errors = validate_fingerprints([_fp("bad", severity="criticl")])
    assert any("invalid severity 'criticl'" in e for e in errors)


@pytest.mark.parametrize("severity", ["low", "medium", "high", "critical"])
def test_all_valid_severities_accepted(severity):
    assert validate_fingerprints([_fp("s", severity=severity)]) == []


def test_invalid_auth_type_is_reported():
    errors = validate_fingerprints([_fp("bad", auth_type="telnet")])
    assert any("invalid auth type 'telnet'" in e for e in errors)


@pytest.mark.parametrize("auth_type", ["basic", "form"])
def test_valid_auth_types_accepted(auth_type):
    assert validate_fingerprints([_fp("a", auth_type=auth_type)]) == []


def test_non_meaningful_match_is_reported():
    errors = validate_fingerprints([_fp("dead", match=MatchCriteria())])
    assert any("never match" in e for e in errors)


def test_no_credentials_is_reported():
    errors = validate_fingerprints([_fp("empty", credentials=[])])
    assert any("no default_credentials" in e for e in errors)


def test_missing_id_is_reported_with_position():
    errors = validate_fingerprints([_fp(id="")])
    assert any("entry 0: missing 'id'" in e for e in errors)


def test_all_errors_are_accumulated_not_just_the_first():
    # One entry violating four rules at once should yield four distinct errors.
    bad = _fp(
        "kitchen-sink",
        severity="nope",
        auth_type="ssh",
        match=MatchCriteria(),
        credentials=[],
    )
    errors = validate_fingerprints([bad])
    assert len(errors) == 4
    joined = "\n".join(errors)
    assert "invalid severity" in joined
    assert "invalid auth type" in joined
    assert "never match" in joined
    assert "no default_credentials" in joined


def test_errors_label_the_offending_fingerprint_by_id():
    errors = validate_fingerprints([_fp("a"), _fp("offender", severity="x")])
    assert any(e.startswith("offender:") for e in errors)


# ------------------------------------------------- FingerprintValidationError / loaders


def test_validation_error_carries_all_errors_and_a_readable_message():
    errs = ["a: bad", "b: also bad"]
    exc = FingerprintValidationError(errs)
    assert exc.errors == errs
    text = str(exc)
    assert "2 fingerprint errors" in text
    assert "a: bad" in text
    assert "b: also bad" in text


def test_validation_error_singular_phrasing_for_one_error():
    assert "1 fingerprint error:" in str(FingerprintValidationError(["x: bad"]))


def test_load_set_with_validate_passes_for_bundled():
    # validate=True must not break loading the clean bundled set.
    fps = load_fingerprint_set("default", validate=True)
    assert len(fps) >= 1


def test_load_set_with_dir_validate_raises_on_bad_custom_set(tmp_path):
    (tmp_path / "default.yaml").write_text(
        """
fingerprints:
  - id: bad-sev
    vendor: V
    severity: criticl
    match: {http_title: X}
    default_credentials: [{username: a, password: b}]
    auth: {type: basic, path: /}
""".lstrip()
    )
    with pytest.raises(FingerprintValidationError) as ei:
        load_fingerprint_set_with_dir(
            "default", fingerprint_dir=tmp_path, validate=True
        )
    assert any("invalid severity" in e for e in ei.value.errors)


def test_load_set_with_dir_validate_passes_for_good_custom_set(tmp_path):
    (tmp_path / "default.yaml").write_text(
        """
fingerprints:
  - id: my-private-cam
    vendor: Private
    severity: high
    match: {http_title: Private}
    default_credentials: [{username: admin, password: admin}]
    auth: {type: basic, path: /login}
""".lstrip()
    )
    fps = load_fingerprint_set_with_dir(
        "default", fingerprint_dir=tmp_path, validate=True
    )
    # bundled + the one custom entry
    assert any(fp.id == "my-private-cam" for fp in fps)


def test_load_without_validate_still_accepts_malformed_entries(tmp_path):
    # Back-compat: the default (validate=False) load path must not start raising.
    (tmp_path / "default.yaml").write_text(
        """
fingerprints:
  - id: bad
    vendor: V
    severity: criticl
    match: {}
    auth: {type: nope}
""".lstrip()
    )
    fps = load_fingerprint_set_with_dir("default", fingerprint_dir=tmp_path)
    assert any(fp.id == "bad" for fp in fps)


# ------------------------------------------------------------------------- CLI --validate


def test_parser_exposes_validate_flag_defaulting_off():
    args = cli.build_parser().parse_args(["--target", "x"])
    assert args.validate is False
    args = cli.build_parser().parse_args(["--validate"])
    assert args.validate is True


def test_cli_validate_clean_set_exits_zero(capsys):
    rc = cli.main(["--validate"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "is valid" in out
    assert "fingerprint(s)" in out


def test_cli_validate_requires_no_target(capsys):
    # No --target supplied and validate still succeeds (it short-circuits before
    # the target requirement).
    rc = cli.main(["--validate"])
    assert rc == 0


def test_cli_validate_bad_custom_set_exits_two_and_reports(tmp_path, capsys):
    (tmp_path / "default.yaml").write_text(
        """
fingerprints:
  - id: dup
    vendor: V
    severity: criticl
    match: {}
    default_credentials: []
    auth: {type: ssh, path: /}
  - id: dup
    vendor: W
    severity: high
    match: {http_title: W}
    default_credentials: [{username: a, password: b}]
    auth: {type: basic, path: /}
""".lstrip()
    )
    rc = cli.main(["--validate", "--fingerprint-dir", str(tmp_path)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "failed validation" in err
    assert "invalid severity" in err
    assert "invalid auth type" in err
    assert "no default_credentials" in err
    # 'dup' is collapsed to one id by the merge, so it's not flagged as a
    # duplicate in the effective set — the per-entry errors are what surface.


def test_cli_validate_never_touches_the_network(tmp_path):
    # validate mode must not construct or run a Scanner.
    with mock.patch.object(cli, "Scanner") as scanner_cls:
        rc = cli.main(["--validate"])
    assert rc == 0
    scanner_cls.assert_not_called()


def test_cli_validate_unknown_set_exits_two(capsys):
    rc = cli.main(["--validate", "--fingerprint-set", "does-not-exist"])
    assert rc == 2
    assert "unknown fingerprint set" in capsys.readouterr().err
