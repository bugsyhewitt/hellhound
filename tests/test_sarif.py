"""Tests for SARIF 2.1.0 output (POST_V01 item 7)."""

import io
import json

from hellhound import cli
from hellhound.fingerprint import Credential
from hellhound.scanner import Finding


def _flagged_finding(
    host="203.0.113.10",
    port=80,
    scheme="http",
    fingerprint_id="hikvision-dvr",
    vendor="Hikvision",
    model_class="DVR / NVR / IP Camera",
    severity="critical",
    cve=None,
) -> Finding:
    return Finding(
        host=host,
        port=port,
        scheme=scheme,
        url=f"{scheme}://{host}:{port}/",
        fingerprint_id=fingerprint_id,
        vendor=vendor,
        model_class=model_class,
        severity=severity,
        default_creds=True,
        matched_credential=Credential("admin", "12345"),
        evidence="default creds authenticated",
        cve=list(cve or []),
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


def test_parser_accepts_sarif_format():
    parser = cli.build_parser()
    args = parser.parse_args(["--target", "192.0.2.1", "--format", "sarif"])
    assert args.format == "sarif"


def test_sarif_top_level_structure():
    out = cli.format_output([_flagged_finding()], "sarif")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert isinstance(doc["runs"], list) and len(doc["runs"]) == 1
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "hellhound"
    assert "version" in driver


def test_sarif_one_result_per_flagged_finding():
    findings = [
        _flagged_finding(host="203.0.113.10"),
        _flagged_finding(host="203.0.113.20", fingerprint_id="dahua-nvr", vendor="Dahua"),
    ]
    doc = json.loads(cli.format_output(findings, "sarif"))
    results = doc["runs"][0]["results"]
    assert len(results) == 2


def test_sarif_omits_rotated_findings():
    """Matched-but-rotated findings are not vulnerabilities; excluded from SARIF."""
    findings = [_flagged_finding(), _rotated_finding()]
    doc = json.loads(cli.format_output(findings, "sarif"))
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "hikvision-dvr"


def test_sarif_location_encodes_host_and_port():
    doc = json.loads(cli.format_output([_flagged_finding(port=8443, scheme="https")], "sarif"))
    loc = doc["runs"][0]["results"][0]["locations"][0]
    uri = loc["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "https://203.0.113.10:8443/"


def test_sarif_severity_maps_to_level():
    cases = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "unknown": "note",
    }
    for severity, expected in cases.items():
        doc = json.loads(
            cli.format_output([_flagged_finding(severity=severity)], "sarif")
        )
        assert doc["runs"][0]["results"][0]["level"] == expected


def test_sarif_includes_cve_properties():
    doc = json.loads(
        cli.format_output([_flagged_finding(cve=["CVE-2024-6047"])], "sarif")
    )
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["cve"] == ["CVE-2024-6047"]
    assert "CVE-2024-6047" in props["tags"]


def test_sarif_rules_deduplicated_by_fingerprint():
    findings = [
        _flagged_finding(host="203.0.113.10"),
        _flagged_finding(host="203.0.113.11"),  # same fingerprint id
    ]
    doc = json.loads(cli.format_output(findings, "sarif"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    # both results reference rule index 0
    for result in doc["runs"][0]["results"]:
        assert result["ruleIndex"] == 0


def test_sarif_empty_findings_is_valid_document():
    doc = json.loads(cli.format_output([], "sarif"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_sarif_via_stream():
    buf = io.StringIO()
    result = cli.format_output([_flagged_finding()], "sarif", stream=buf)
    assert result is None
    doc = json.loads(buf.getvalue())
    assert doc["version"] == "2.1.0"


def test_main_sarif_to_stdout(monkeypatch, capsys):
    findings = [_flagged_finding(), _rotated_finding()]

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(["--target", "203.0.113.10", "--format", "sarif"])
    assert exit_code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"][0]["results"]) == 1


def test_main_sarif_output_file_round_trip(monkeypatch, capsys, tmp_path):
    findings = [_flagged_finding(cve=["CVE-2024-6047"])]

    async def fake_scan(self, targets, ports, **kwargs):
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    out_path = tmp_path / "results.sarif"
    exit_code = cli.main(
        ["--target", "203.0.113.10", "--format", "sarif", "--output-file", str(out_path)]
    )
    assert exit_code == 0
    assert capsys.readouterr().out == ""
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"][0]["properties"]["cve"] == ["CVE-2024-6047"]
