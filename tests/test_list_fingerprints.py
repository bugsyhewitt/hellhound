"""Tests for the --list-fingerprints inventory mode.

Inventory mode prints the loaded fingerprint database (after any
--fingerprint-dir merge) and exits without scanning. It honours --format
(json/text/csv) and --output-file, and requires no target. These tests cover
the parser surface, the three render formats, the CLI short-circuit (including
that the scanner is never invoked), the custom-directory merge view, and the
output-file path.
"""

import csv
import io
import json

import pytest

from hellhound import cli
from hellhound.fingerprint import (
    AuthCheck,
    Credential,
    Fingerprint,
    MatchCriteria,
)


def _sample_fingerprints() -> list[Fingerprint]:
    return [
        Fingerprint(
            id="acme-cam",
            vendor="Acme",
            model_class="IP Camera",
            severity="critical",
            match=MatchCriteria(http_title="Acme"),
            credentials=[
                Credential("admin", "admin"),
                Credential("root", ""),
            ],
            auth=AuthCheck(type="basic", path="/login"),
            cve=("CVE-2025-0001",),
        ),
        Fingerprint(
            id="beta-router",
            vendor="Beta",
            model_class="SOHO Router",
            severity="high",
            match=MatchCriteria(http_title="Beta"),
            credentials=[Credential("admin", "password")],
            auth=AuthCheck(type="form", path="/cgi-bin/login"),
        ),
    ]


# ----------------------------------------------------------------- parser surface


def test_parser_list_fingerprints_defaults_false():
    parser = cli.build_parser()
    args = parser.parse_args(["--target", "192.0.2.1"])
    assert args.list_fingerprints is False


def test_parser_list_fingerprints_flag_sets_true():
    parser = cli.build_parser()
    args = parser.parse_args(["--list-fingerprints"])
    assert args.list_fingerprints is True


def test_parser_target_not_required_with_list_flag():
    """--target is no longer hard-required; main() validates the combination."""
    parser = cli.build_parser()
    args = parser.parse_args(["--list-fingerprints"])
    assert args.target is None


# ----------------------------------------------------------------- formatters


def test_format_fingerprint_list_text():
    out = cli.format_fingerprint_list(_sample_fingerprints(), "text")
    assert "2 fingerprint(s) loaded" in out
    assert "acme-cam" in out
    assert "[CRITICAL]" in out
    assert "Acme (IP Camera)" in out
    # blank password renders as 'root:' so empty defaults stay visible
    assert "admin:admin;root:" in out
    # CVE shown inline
    assert "CVE-2025-0001" in out


def test_format_fingerprint_list_json():
    out = cli.format_fingerprint_list(_sample_fingerprints(), "json")
    parsed = json.loads(out)
    assert parsed["summary"]["fingerprint_count"] == 2
    first = parsed["fingerprints"][0]
    assert first["id"] == "acme-cam"
    assert first["auth_type"] == "basic"
    assert first["auth_path"] == "/login"
    assert first["cve"] == ["CVE-2025-0001"]
    assert first["default_credentials"] == [
        {"username": "admin", "password": "admin"},
        {"username": "root", "password": ""},
    ]
    # entry with no CVE serialises to an empty list, not null
    assert parsed["fingerprints"][1]["cve"] == []


def test_format_fingerprint_list_csv():
    out = cli.format_fingerprint_list(_sample_fingerprints(), "csv")
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0] == cli.FINGERPRINT_LIST_COLUMNS
    assert rows[1][0] == "acme-cam"
    assert rows[1][4] == "basic"  # auth_type column
    assert rows[1][6] == "admin:admin;root:"  # default_credentials column
    assert rows[1][7] == "CVE-2025-0001"  # cve column
    # second row has empty cve cell
    assert rows[2][7] == ""


def test_format_fingerprint_list_sarif_falls_back_to_json():
    """SARIF is not a meaningful inventory format; it must yield JSON."""
    out = cli.format_fingerprint_list(_sample_fingerprints(), "sarif")
    parsed = json.loads(out)
    assert "fingerprints" in parsed
    assert parsed["summary"]["fingerprint_count"] == 2


# ----------------------------------------------------------------- main() wiring


def test_main_list_fingerprints_no_target(capsys, monkeypatch):
    """Inventory mode runs with no --target and never touches the scanner."""

    async def boom(self, *a, **k):  # pragma: no cover - must not be called
        raise AssertionError("scan must not run in --list-fingerprints mode")

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", boom)

    exit_code = cli.main(["--list-fingerprints", "--format", "json"])
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert exit_code == 0
    # the bundled default set has its full complement of fingerprints
    assert parsed["summary"]["fingerprint_count"] >= 12
    assert parsed["summary"]["fingerprint_count"] == len(parsed["fingerprints"])


def test_main_list_fingerprints_default_format_is_json(capsys):
    """Default --format is json, matching the scan path."""
    exit_code = cli.main(["--list-fingerprints"])
    out = capsys.readouterr().out
    assert exit_code == 0
    parsed = json.loads(out)
    assert parsed["summary"]["fingerprint_count"] >= 12


def test_main_list_fingerprints_text_format(capsys):
    exit_code = cli.main(["--list-fingerprints", "--format", "text"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "fingerprint(s) loaded" in out


def test_main_requires_target_without_list_flag(capsys):
    exit_code = cli.main([])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "--target is required" in err


def test_main_list_fingerprints_to_output_file(capsys, tmp_path):
    out_path = tmp_path / "inventory.csv"
    exit_code = cli.main(
        [
            "--list-fingerprints",
            "--format",
            "csv",
            "--output-file",
            str(out_path),
        ]
    )
    assert exit_code == 0
    # nothing on stdout when writing to a file
    assert capsys.readouterr().out == ""
    content = out_path.read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(content)))
    assert rows[0] == cli.FINGERPRINT_LIST_COLUMNS
    assert len(rows) >= 13  # header + bundled fingerprints


def test_main_list_fingerprints_unwritable_output_errors(capsys, tmp_path):
    bad = tmp_path / "missing-dir" / "out.csv"
    exit_code = cli.main(
        ["--list-fingerprints", "--output-file", str(bad)]
    )
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "could not write output file" in err


def test_main_list_fingerprints_reflects_custom_dir_merge(capsys, tmp_path):
    """A custom --fingerprint-dir entry shows up in the inventory."""
    custom = tmp_path / "default.yaml"
    custom.write_text(
        "fingerprints:\n"
        "  - id: my-private-device\n"
        "    vendor: PrivateCo\n"
        "    model_class: Widget\n"
        "    severity: high\n"
        "    match:\n"
        "      http_title: PrivateCo\n"
        "    default_credentials:\n"
        "      - {username: admin, password: secret}\n"
        "    auth:\n"
        "      type: basic\n"
        "      path: /\n",
        encoding="utf-8",
    )
    exit_code = cli.main(
        [
            "--list-fingerprints",
            "--fingerprint-dir",
            str(tmp_path),
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert exit_code == 0
    ids = [fp["id"] for fp in parsed["fingerprints"]]
    assert "my-private-device" in ids
    # bundled entries are preserved alongside the custom one
    assert len(ids) >= 13


def test_format_credentials_empty():
    fp = Fingerprint(
        id="x",
        vendor="X",
        model_class="Y",
        severity="low",
        match=MatchCriteria(http_title="X"),
        credentials=[],
        auth=AuthCheck(),
    )
    assert cli._format_credentials(fp) == ""
