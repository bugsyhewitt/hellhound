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
    "cve",
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

    async def fake_scan(self, targets, ports, **kwargs):
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

    async def fake_scan(self, targets, ports, **kwargs):
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

    async def fake_scan(self, targets, ports, **kwargs):
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

    async def fake_scan(self, targets, ports, **kwargs):
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

    async def fake_scan(self, targets, ports, **kwargs):
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


# ---------------------------------------------------------------- --only-vulnerable


def test_parser_only_vulnerable_defaults_false():
    parser = cli.build_parser()
    args = parser.parse_args(["--target", "192.0.2.1"])
    assert args.only_vulnerable is False


def test_parser_only_vulnerable_flag_sets_true():
    parser = cli.build_parser()
    args = parser.parse_args(["--target", "192.0.2.1", "--only-vulnerable"])
    assert args.only_vulnerable is True


def test_format_json_only_vulnerable_filters_findings():
    """Digest mode drops matched-but-rotated findings; summary keeps totals."""
    out = cli.format_output(_mixed_findings(), "json", only_vulnerable=True)
    parsed = json.loads(out)
    # summary reflects ALL matches
    assert parsed["summary"]["devices_matched"] == 2
    assert parsed["summary"]["devices_with_default_creds"] == 1
    assert parsed["summary"]["only_vulnerable"] is True
    # findings list only contains the flagged device
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["vendor"] == "Hikvision"
    assert parsed["findings"][0]["default_creds"] is True


def test_format_json_default_includes_all_findings():
    out = cli.format_output(_mixed_findings(), "json")
    parsed = json.loads(out)
    assert parsed["summary"]["only_vulnerable"] is False
    assert len(parsed["findings"]) == 2


def test_format_csv_only_vulnerable_filters_rows():
    out = cli.format_output(_mixed_findings(), "csv", only_vulnerable=True)
    rows = list(csv.reader(io.StringIO(out)))
    # header + only the flagged row
    assert rows[0] == CSV_COLUMNS
    assert len(rows) == 2
    assert dict(zip(CSV_COLUMNS, rows[1]))["vendor"] == "Hikvision"


def test_format_text_only_vulnerable_omits_rotated():
    out = cli.format_output(_mixed_findings(), "text", only_vulnerable=True)
    # summary line still mentions the full matched count
    assert "2 device(s) matched" in out
    # rotated finding's vendor is suppressed from the body
    assert "Dahua" not in out
    assert "Hikvision" in out


def test_main_only_vulnerable_end_to_end(monkeypatch, capsys):
    findings = _mixed_findings()

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(
        ["--target", "203.0.113.10", "--format", "json", "--only-vulnerable"]
    )
    assert exit_code == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["summary"]["devices_matched"] == 2
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["vendor"] == "Hikvision"


def test_main_only_vulnerable_output_file(monkeypatch, capsys, tmp_path):
    findings = _mixed_findings()

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    out_path = tmp_path / "digest.csv"
    exit_code = cli.main(
        [
            "--target",
            "203.0.113.10",
            "--format",
            "csv",
            "--only-vulnerable",
            "--output-file",
            str(out_path),
        ]
    )
    assert exit_code == 0
    assert capsys.readouterr().out == ""
    rows = list(csv.reader(out_path.open(newline="", encoding="utf-8")))
    assert rows[0] == CSV_COLUMNS
    assert len(rows) == 2  # header + 1 flagged row
    assert dict(zip(CSV_COLUMNS, rows[1]))["vendor"] == "Hikvision"


# ================================================================ Additional CLI tests


from hellhound.fingerprint import (  # noqa: E402
    AuthCheck,
    Fingerprint,
    MatchCriteria,
)


def _cve_finding() -> list[Finding]:
    return [
        Finding(
            host="192.0.2.5",
            port=443,
            scheme="https",
            url="https://192.0.2.5:443/",
            fingerprint_id="aruba-ap",
            vendor="HPE Aruba",
            model_class="Access Point",
            severity="critical",
            default_creds=True,
            matched_credential=Credential("admin", "default123"),
            evidence="default creds authenticated",
            cve=["CVE-2025-37103"],
        )
    ]


# ------------------------------------------------------------------ --version


def test_version_flag_exits_zero(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "hellhound" in (captured.out + captured.err)


# ------------------------------------------------------------------ --format sarif


def test_format_sarif_output_is_valid_json():
    out = cli.format_output(_sample_findings(), "sarif")
    parsed = json.loads(out)
    assert parsed["version"] == "2.1.0"
    assert "runs" in parsed
    assert len(parsed["runs"]) == 1


def test_format_sarif_only_includes_flagged_findings():
    out = cli.format_output(_mixed_findings(), "sarif")
    parsed = json.loads(out)
    results = parsed["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "hikvision-dvr"


def test_format_sarif_critical_maps_to_error_level():
    out = cli.format_output(_sample_findings(), "sarif")
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    assert result["level"] == "error"


def test_format_sarif_cve_in_result_properties():
    out = cli.format_output(_cve_finding(), "sarif")
    parsed = json.loads(out)
    result = parsed["runs"][0]["results"][0]
    assert "CVE-2025-37103" in result["properties"]["cve"]


def test_format_sarif_no_flagged_findings_empty_results():
    rotated = [
        Finding(
            host="192.0.2.1", port=80, scheme="http", url="http://192.0.2.1:80/",
            fingerprint_id="fp", vendor="V", model_class="cam", severity="high",
            default_creds=False, matched_credential=None, evidence="rotated",
        )
    ]
    out = cli.format_output(rotated, "sarif")
    parsed = json.loads(out)
    assert parsed["runs"][0]["results"] == []


def test_sarif_level_function_critical():
    assert cli._sarif_level("critical") == "error"


def test_sarif_level_function_high():
    assert cli._sarif_level("high") == "error"


def test_sarif_level_function_medium():
    assert cli._sarif_level("medium") == "warning"


def test_sarif_level_function_low():
    assert cli._sarif_level("low") == "note"


def test_sarif_level_function_unknown():
    assert cli._sarif_level("") == "note"


# ------------------------------------------------------------------ hosts_scanned in summary


def test_format_json_includes_hosts_scanned():
    out = cli.format_output(_sample_findings(), "json", hosts_scanned=254)
    parsed = json.loads(out)
    assert parsed["summary"]["hosts_scanned"] == 254


def test_format_json_no_hosts_scanned_omits_field():
    out = cli.format_output(_sample_findings(), "json")
    parsed = json.loads(out)
    assert "hosts_scanned" not in parsed["summary"]


def test_format_text_includes_hosts_scanned():
    out = cli.format_output(_sample_findings(), "text", hosts_scanned=10)
    assert "10 host(s) scanned" in out


def test_main_json_output_has_hosts_scanned(monkeypatch, capsys):
    findings = _sample_findings()

    async def fake_scan(self, targets, ports, **kwargs):
        self.last_hosts_scanned = 1
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)
    cli.main(["--target", "192.0.2.1"])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert "hosts_scanned" in parsed["summary"]


# ------------------------------------------------------------------ --exit-code


def test_resolve_exit_code_zero_when_no_findings():
    assert cli.resolve_exit_code([], exit_code_when_found=1) == 0


def test_resolve_exit_code_zero_when_exit_code_is_zero():
    assert cli.resolve_exit_code(_sample_findings(), exit_code_when_found=0) == 0


def test_resolve_exit_code_returns_configured_code_when_findings():
    assert cli.resolve_exit_code(_sample_findings(), exit_code_when_found=1) == 1


def test_resolve_exit_code_uses_configured_code():
    assert cli.resolve_exit_code(_sample_findings(), exit_code_when_found=42) == 42


def test_resolve_exit_code_zero_when_no_flagged_findings():
    rotated = [
        Finding(
            host="x", port=80, scheme="http", url="http://x/",
            fingerprint_id="fp", vendor="V", model_class="c", severity="high",
            default_creds=False, matched_credential=None, evidence="rotated",
        )
    ]
    assert cli.resolve_exit_code(rotated, exit_code_when_found=1) == 0


def test_main_exit_code_flag_nonzero_when_findings(monkeypatch):
    async def fake_scan(self, targets, ports, **kwargs):
        self.last_hosts_scanned = 1
        return _sample_findings()

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)
    exit_code = cli.main(["--target", "192.0.2.1", "--exit-code", "1", "--quiet"])
    assert exit_code == 1


# ------------------------------------------------------------------ --list-fingerprints


def test_list_fingerprints_json_output(capsys):
    rc = cli.main(["--list-fingerprints", "--format", "json"])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert "fingerprints" in parsed
    assert parsed["summary"]["fingerprint_count"] >= 10


def test_list_fingerprints_text_output(capsys):
    rc = cli.main(["--list-fingerprints", "--format", "text"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "hellhound:" in out
    assert "fingerprint(s) loaded" in out


def test_list_fingerprints_csv_output(capsys):
    rc = cli.main(["--list-fingerprints", "--format", "csv"])
    assert rc == 0
    out = capsys.readouterr().out
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0][0] == "id"


def test_list_fingerprints_to_file(tmp_path, capsys):
    out_path = tmp_path / "fingerprints.json"
    rc = cli.main(
        ["--list-fingerprints", "--format", "json", "--output-file", str(out_path)]
    )
    assert rc == 0
    assert out_path.exists()
    parsed = json.loads(out_path.read_text())
    assert "fingerprints" in parsed


def test_format_fingerprint_list_sarif_falls_back_to_json():
    from hellhound.fingerprint import load_fingerprint_set

    fps = load_fingerprint_set("default")
    out = cli.format_fingerprint_list(fps, "sarif")
    parsed = json.loads(out)
    assert "fingerprints" in parsed


def test_list_fingerprints_no_target_required(capsys):
    rc = cli.main(["--list-fingerprints"])
    assert rc == 0


# ------------------------------------------------------------------ --progress / --quiet


def test_resolve_progress_enabled_quiet_wins():
    assert cli.resolve_progress_enabled(True, quiet=True) is False


def test_resolve_progress_enabled_explicit_progress_flag():
    assert cli.resolve_progress_enabled(True, quiet=False) is True


def test_resolve_progress_enabled_auto_non_tty():
    class FakeStream:
        def isatty(self):
            return False

    assert cli.resolve_progress_enabled(None, quiet=False, stream=FakeStream()) is False


def test_resolve_progress_enabled_auto_tty():
    class FakeTTY:
        def isatty(self):
            return True

    assert cli.resolve_progress_enabled(None, quiet=False, stream=FakeTTY()) is True


def test_make_progress_callback_writes_progress():
    buf = io.StringIO()
    callback = cli.make_progress_callback(stream=buf)
    from hellhound.scanner import ScanProgress
    callback(ScanProgress(hosts_done=5, hosts_total=10, findings_with_default_creds=1))
    output = buf.getvalue()
    assert "5/10" in output
    assert "1 with default creds" in output


def test_make_progress_callback_final_host_adds_newline():
    buf = io.StringIO()
    callback = cli.make_progress_callback(stream=buf)
    from hellhound.scanner import ScanProgress
    callback(ScanProgress(hosts_done=10, hosts_total=10, findings_with_default_creds=2))
    assert buf.getvalue().endswith("\n")


# ------------------------------------------------------------------ parse_ports edge cases


def test_parse_ports_out_of_range_raises():
    with pytest.raises(ValueError, match="out of range"):
        cli.parse_ports("0")
    with pytest.raises(ValueError, match="out of range"):
        cli.parse_ports("65536")


def test_parse_ports_empty_string_raises():
    with pytest.raises(ValueError, match="no valid ports"):
        cli.parse_ports("")


def test_parse_ports_port_1_and_65535_valid():
    assert cli.parse_ports("1,65535") == [1, 65535]


# ------------------------------------------------------------------ --no-target error


def test_main_no_target_errors(capsys):
    rc = cli.main([])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--target" in err or "target" in err.lower()


# ------------------------------------------------------------------ CVE in findings


def test_format_json_cve_in_finding():
    out = cli.format_output(_cve_finding(), "json")
    parsed = json.loads(out)
    assert parsed["findings"][0]["cve"] == ["CVE-2025-37103"]


def test_format_csv_cve_column():
    out = cli.format_output(_cve_finding(), "csv")
    rows = list(csv.reader(io.StringIO(out)))
    record = dict(zip(CSV_COLUMNS, rows[1]))
    assert "CVE-2025-37103" in record["cve"]
