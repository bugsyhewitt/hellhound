"""Tests for the argparse CLI surface and output formatting."""

import csv
import io
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
    assert hasattr(args, "output_file")
    assert args.output_file is None


def test_parser_accepts_csv_and_output_file():
    parser = cli.build_parser()
    args = parser.parse_args(
        ["--target", "192.0.2.1", "--format", "csv", "--output-file", "/tmp/out.csv"]
    )
    assert args.format == "csv"
    assert args.output_file == "/tmp/out.csv"


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


def _mixed_findings() -> list[Finding]:
    """One flagged finding plus one matched-but-rotated finding."""
    return _sample_findings() + [
        Finding(
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


CSV_COLUMNS = [
    "host",
    "port",
    "scheme",
    "vendor",
    "model_class",
    "severity",
    "fingerprint_id",
    "default_creds",
    "username",
    "password",
    "evidence",
]


def test_format_csv_header_and_data_rows():
    out = cli.format_output(_mixed_findings(), "csv")
    rows = list(csv.reader(io.StringIO(out)))
    # header + 2 data rows
    assert rows[0] == CSV_COLUMNS
    assert len(rows) == 3

    flagged = rows[1]
    record = dict(zip(CSV_COLUMNS, flagged))
    assert record["host"] == "203.0.113.10"
    assert record["port"] == "80"
    assert record["vendor"] == "Hikvision"
    assert record["default_creds"] == "true"
    assert record["username"] == "admin"
    assert record["password"] == "12345"

    rotated = dict(zip(CSV_COLUMNS, rows[2]))
    assert rotated["vendor"] == "Dahua"
    assert rotated["default_creds"] == "false"
    # no matched credential -> empty username/password cells
    assert rotated["username"] == ""
    assert rotated["password"] == ""


def test_format_csv_empty_findings_still_has_header():
    out = cli.format_output([], "csv")
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == CSV_COLUMNS
    assert len(rows) == 1


def test_format_output_accepts_stream():
    """format_output writes to the supplied stream and returns None."""
    buf = io.StringIO()
    result = cli.format_output(_sample_findings(), "json", stream=buf)
    assert result is None
    parsed = json.loads(buf.getvalue())
    assert parsed["findings"][0]["vendor"] == "Hikvision"


def test_main_csv_output_file_round_trip(monkeypatch, capsys, tmp_path):
    """--format csv --output-file writes a CSV file; stdout stays empty."""
    findings = _mixed_findings()

    async def fake_scan(self, targets, ports):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    out_path = tmp_path / "results.csv"
    exit_code = cli.main(
        [
            "--target",
            "203.0.113.10",
            "--format",
            "csv",
            "--output-file",
            str(out_path),
        ]
    )
    assert exit_code == 0

    # stdout must be empty when writing to a file
    captured = capsys.readouterr()
    assert captured.out == ""

    assert out_path.exists()
    rows = list(csv.reader(out_path.open(newline="", encoding="utf-8")))
    assert rows[0] == CSV_COLUMNS
    assert len(rows) == 3
    assert dict(zip(CSV_COLUMNS, rows[1]))["vendor"] == "Hikvision"


def test_main_json_output_file_round_trip(monkeypatch, capsys, tmp_path):
    findings = _sample_findings()

    async def fake_scan(self, targets, ports):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    out_path = tmp_path / "results.json"
    exit_code = cli.main(
        ["--target", "203.0.113.10", "--format", "json", "--output-file", str(out_path)]
    )
    assert exit_code == 0
    assert capsys.readouterr().out == ""
    parsed = json.loads(out_path.read_text(encoding="utf-8"))
    assert parsed["findings"][0]["vendor"] == "Hikvision"


def test_main_csv_to_stdout(monkeypatch, capsys):
    """Without --output-file, csv goes to stdout."""
    findings = _sample_findings()

    async def fake_scan(self, targets, ports):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(["--target", "203.0.113.10", "--format", "csv"])
    assert exit_code == 0
    out = capsys.readouterr().out
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == CSV_COLUMNS
    assert len(rows) == 2


def test_main_output_file_unwritable_errors(monkeypatch, capsys):
    findings = _sample_findings()

    async def fake_scan(self, targets, ports):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    # a path whose parent directory does not exist
    exit_code = cli.main(
        ["--target", "203.0.113.10", "--output-file", "/nonexistent-dir-xyz/out.json"]
    )
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "output" in err.lower() or "error" in err.lower()


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
