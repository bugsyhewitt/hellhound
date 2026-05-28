"""Tests for the findings-based --exit-code flag.

``--exit-code N`` lets hellhound return a non-zero exit status when it finds a
confirmed default-credential exposure, so it can gate a CI/CD pipeline or a
shell script. The default (0) preserves the original contract: a successful
scan always exits 0 regardless of findings.
"""

import json

import pytest

from hellhound import cli
from hellhound.fingerprint import Credential
from hellhound.scanner import Finding


def _flagged_finding() -> Finding:
    return Finding(
        host="203.0.113.10",
        port=80,
        scheme="http",
        url="http://203.0.113.10:80/",
        fingerprint_id="hikvision-dvr",
        vendor="Hikvision",
        model_class="DVR / NVR / IP Camera",
        severity="critical",
        default_creds=True,
        matched_credential=Credential("admin", "12345"),
        evidence="default creds authenticated",
    )


def _rotated_finding() -> Finding:
    return Finding(
        host="203.0.113.11",
        port=443,
        scheme="https",
        url="https://203.0.113.11:443/",
        fingerprint_id="dahua-nvr",
        vendor="Dahua",
        model_class="NVR",
        severity="high",
        default_creds=False,
        matched_credential=None,
        evidence="matched Dahua fingerprint; default credentials rejected",
    )


# ---------------------------------------------------------------- parser surface


def test_parser_exit_code_defaults_zero():
    parser = cli.build_parser()
    args = parser.parse_args(["--target", "192.0.2.1"])
    assert args.exit_code == 0


def test_parser_exit_code_accepts_value():
    parser = cli.build_parser()
    args = parser.parse_args(["--target", "192.0.2.1", "--exit-code", "1"])
    assert args.exit_code == 1


def test_parser_exit_code_rejects_non_int():
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--target", "192.0.2.1", "--exit-code", "abc"])


# ---------------------------------------------------------------- resolve helper


def test_resolve_exit_code_default_zero_is_always_zero():
    # Even with a flagged finding, a 0 "when found" value preserves exit 0.
    assert cli.resolve_exit_code([_flagged_finding()], 0) == 0


def test_resolve_exit_code_returns_value_when_exposure_found():
    assert cli.resolve_exit_code([_flagged_finding()], 1) == 1


def test_resolve_exit_code_custom_nonzero_value():
    assert cli.resolve_exit_code([_flagged_finding()], 7) == 7


def test_resolve_exit_code_zero_when_no_exposure():
    # A matched-but-rotated finding is not an exposure -> exit 0.
    assert cli.resolve_exit_code([_rotated_finding()], 1) == 0


def test_resolve_exit_code_zero_on_empty_findings():
    assert cli.resolve_exit_code([], 1) == 0


def test_resolve_exit_code_mixed_findings_returns_value():
    findings = [_rotated_finding(), _flagged_finding()]
    assert cli.resolve_exit_code(findings, 1) == 1


# ---------------------------------------------------------------- end to end


def test_main_exit_code_nonzero_on_exposure(monkeypatch, capsys):
    findings = [_flagged_finding()]

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(
        ["--target", "203.0.113.10", "--format", "json", "--exit-code", "1"]
    )
    assert exit_code == 1
    # output is unchanged — the findings are still printed
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["findings"][0]["vendor"] == "Hikvision"


def test_main_exit_code_zero_when_no_exposure(monkeypatch, capsys):
    findings = [_rotated_finding()]

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(
        ["--target", "203.0.113.11", "--format", "json", "--exit-code", "1"]
    )
    assert exit_code == 0
    parsed = json.loads(capsys.readouterr().out)
    # the rotated match is still reported, it just isn't an exposure
    assert parsed["summary"]["devices_matched"] == 1
    assert parsed["summary"]["devices_with_default_creds"] == 0


def test_main_default_exit_zero_even_with_exposure(monkeypatch, capsys):
    """Without --exit-code, an exposure still exits 0 (back-compatible)."""
    findings = [_flagged_finding()]

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(["--target", "203.0.113.10", "--format", "json"])
    assert exit_code == 0
    capsys.readouterr()


def test_main_exit_code_applies_to_output_file(monkeypatch, capsys, tmp_path):
    findings = [_flagged_finding()]

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    out_path = tmp_path / "findings.json"
    exit_code = cli.main(
        [
            "--target",
            "203.0.113.10",
            "--format",
            "json",
            "--exit-code",
            "1",
            "--output-file",
            str(out_path),
        ]
    )
    assert exit_code == 1
    assert capsys.readouterr().out == ""
    parsed = json.loads(out_path.read_text(encoding="utf-8"))
    assert parsed["findings"][0]["vendor"] == "Hikvision"


def test_main_exit_code_independent_of_only_vulnerable(monkeypatch, capsys):
    """--only-vulnerable filters display but the exit signal stays stable."""
    findings = [_rotated_finding(), _flagged_finding()]

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(
        [
            "--target",
            "203.0.113.10",
            "--format",
            "json",
            "--only-vulnerable",
            "--exit-code",
            "2",
        ]
    )
    assert exit_code == 2
    parsed = json.loads(capsys.readouterr().out)
    # display filtered to the exposure, summary still reflects both matches
    assert parsed["summary"]["devices_matched"] == 2
    assert len(parsed["findings"]) == 1


def test_main_exit_code_does_not_affect_input_errors(capsys):
    """Argument/input errors keep their exit 2 regardless of --exit-code."""
    exit_code = cli.main(
        ["--target", "203.0.113.10", "--fingerprint-set", "nope", "--exit-code", "1"]
    )
    assert exit_code == 2
    assert "fingerprint" in capsys.readouterr().err.lower()


def test_main_exit_code_unaffected_by_list_fingerprints(capsys):
    """Inventory mode is detection-only; --exit-code never makes it non-zero."""
    exit_code = cli.main(["--list-fingerprints", "--exit-code", "1"])
    assert exit_code == 0
    assert capsys.readouterr().out  # something was printed
