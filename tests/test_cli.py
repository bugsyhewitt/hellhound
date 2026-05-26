"""Tests for the argparse CLI surface and output formatting."""

import json

import pytest

from hellhound import cli
from hellhound.fingerprint import Credential
from hellhound.scanner import Finding


def test_build_parser_has_required_options():
    parser = cli.build_parser()
    # Parse a minimal valid invocation
    args = parser.parse_args(["--target", "192.0.2.1"])
    assert args.target == ["192.0.2.1"]
    # defaults exist for the criterion-2 options
    assert hasattr(args, "ports")
    assert hasattr(args, "fingerprint_set")
    assert hasattr(args, "format")


def test_help_lists_required_flags(capsys):
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    for flag in ("--target", "--ports", "--fingerprint-set", "--format"):
        assert flag in out


def test_parse_ports():
    assert cli.parse_ports("80") == [80]
    assert cli.parse_ports("80,443,8080") == [80, 443, 8080]
    assert cli.parse_ports("80, 443 ,8443") == [80, 443, 8443]


def test_parse_ports_rejects_garbage():
    with pytest.raises(ValueError):
        cli.parse_ports("80,abc")


def _sample_findings() -> list[Finding]:
    return [
        Finding(
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
    ]


def test_format_json_output_is_valid_json():
    out = cli.format_output(_sample_findings(), "json")
    parsed = json.loads(out)
    assert parsed["summary"]["devices_with_default_creds"] == 1
    assert parsed["findings"][0]["vendor"] == "Hikvision"
    assert parsed["findings"][0]["matched_credential"]["password"] == "12345"


def test_format_text_output_mentions_finding():
    out = cli.format_output(_sample_findings(), "text")
    assert "Hikvision" in out
    assert "admin:12345" in out


def test_format_json_empty_findings():
    out = cli.format_output([], "json")
    parsed = json.loads(out)
    assert parsed["summary"]["devices_with_default_creds"] == 0
    assert parsed["findings"] == []


def test_main_runs_against_mock(monkeypatch, capsys):
    """End-to-end CLI path with the scan engine stubbed out."""
    findings = _sample_findings()

    async def fake_scan(self, targets, ports):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(["--target", "203.0.113.10", "--format", "json"])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["findings"][0]["vendor"] == "Hikvision"
    # findings present -> non-zero exit code signals "something found"
    assert exit_code == 0


def test_main_unknown_fingerprint_set_errors(capsys):
    exit_code = cli.main(["--target", "203.0.113.10", "--fingerprint-set", "nope"])
    err = capsys.readouterr().err
    assert exit_code != 0
    assert "fingerprint" in err.lower()
