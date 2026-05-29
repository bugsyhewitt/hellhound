"""Tests for the ``hosts_scanned`` sweep-denominator summary field.

The persistent output artefact (json/text/csv) historically reported only how
many devices *matched* a fingerprint and how many were *exposed*, never how
many hosts were actually probed. The transient ``--progress`` stderr line knew
the denominator, but it is off when output is piped to a file — exactly the
analyst-triage workflow. This change threads the post-exclusion host count
(``Scanner.last_hosts_scanned``) into the json/text summary as ``hosts_scanned``
so "matched X of Y scanned" survives in the saved report.

The field is opt-in: ``format_output``/``_render`` default ``hosts_scanned`` to
``None``, which omits it and preserves the original summary shape, so callers
that don't know the count are unaffected.
"""

import asyncio
import csv
import io
import ipaddress
import json

import httpx

from hellhound import cli
from hellhound.fingerprint import (
    AuthCheck,
    Credential,
    Fingerprint,
    MatchCriteria,
)
from hellhound.scanner import Finding, Scanner


def run(coro):
    return asyncio.run(coro)


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


# ----------------------------------------------------------------- formatter unit

def test_json_summary_includes_hosts_scanned_when_provided():
    out = cli.format_output(_sample_findings(), "json", hosts_scanned=254)
    summary = json.loads(out)["summary"]
    assert summary["hosts_scanned"] == 254
    # existing fields untouched
    assert summary["devices_matched"] == 1
    assert summary["devices_with_default_creds"] == 1


def test_json_summary_omits_hosts_scanned_by_default():
    """Back-compat: with no count, the field is absent (original shape)."""
    out = cli.format_output(_sample_findings(), "json")
    summary = json.loads(out)["summary"]
    assert "hosts_scanned" not in summary


def test_json_summary_hosts_scanned_zero_is_reported():
    """Zero hosts (e.g. everything excluded) must still surface, not vanish."""
    out = cli.format_output([], "json", hosts_scanned=0)
    summary = json.loads(out)["summary"]
    assert summary["hosts_scanned"] == 0
    assert summary["devices_matched"] == 0


def test_text_summary_includes_hosts_scanned_when_provided():
    out = cli.format_output(_sample_findings(), "text", hosts_scanned=254)
    first_line = out.splitlines()[0]
    assert "254 host(s) scanned" in first_line
    assert "1 device(s) matched" in first_line


def test_text_summary_omits_hosts_scanned_by_default():
    out = cli.format_output(_sample_findings(), "text")
    assert "scanned" not in out.splitlines()[0]


def test_hosts_scanned_composes_with_only_vulnerable():
    """Digest mode keeps full summary counts and still carries the denominator."""
    out = cli.format_output(
        _sample_findings(), "json", only_vulnerable=True, hosts_scanned=100
    )
    summary = json.loads(out)["summary"]
    assert summary["hosts_scanned"] == 100
    assert summary["only_vulnerable"] is True


def test_csv_output_unaffected_by_hosts_scanned():
    """CSV is row-per-finding (no summary block); the arg must be a harmless no-op."""
    without = cli.format_output(_sample_findings(), "csv")
    with_count = cli.format_output(_sample_findings(), "csv", hosts_scanned=254)
    assert without == with_count
    rows = list(csv.reader(io.StringIO(with_count)))
    assert rows[0] == cli.CSV_COLUMNS


# ----------------------------------------------------------------- scanner attr

def _match_all_fingerprint() -> Fingerprint:
    return Fingerprint(
        id="any",
        vendor="Any",
        model_class="thing",
        severity="low",
        match=MatchCriteria(body_contains="hello"),
        credentials=[Credential("admin", "admin")],
        auth=AuthCheck(type="basic", path="/", success_status=(401,)),
    )


def _never_match_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        # body never contains the needle -> no fingerprint match, but the host
        # WAS probed, which is the count we care about.
        return httpx.Response(200, text="<html>nothing here</html>")

    return httpx.MockTransport(handler)


def test_scanner_records_last_hosts_scanned():
    scanner = Scanner(
        fingerprints=[_match_all_fingerprint()],
        transport=_never_match_transport(),
    )
    assert scanner.last_hosts_scanned is None
    # /30 -> 2 usable hosts
    run(scanner.scan(["203.0.113.0/30"], [80]))
    assert scanner.last_hosts_scanned == 2


def test_scanner_last_hosts_scanned_respects_exclusions():
    scanner = Scanner(
        fingerprints=[_match_all_fingerprint()],
        transport=_never_match_transport(),
    )
    exclusions = [ipaddress.ip_network("203.0.113.1/32")]
    # /30 -> .1 and .2 usable; exclude .1 -> 1 host probed
    run(scanner.scan(["203.0.113.0/30"], [80], exclusions=exclusions))
    assert scanner.last_hosts_scanned == 1


# ----------------------------------------------------------------- end-to-end CLI

def test_main_json_reports_hosts_scanned(monkeypatch, capsys):
    """The CLI threads Scanner.last_hosts_scanned into the printed summary."""
    findings = _sample_findings()

    async def fake_scan(self, targets, ports, **kwargs):
        # mimic the real scan setting the attribute as a side effect
        self.last_hosts_scanned = 254
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(["--target", "203.0.113.0/24", "--format", "json"])
    assert exit_code == 0
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert summary["hosts_scanned"] == 254


def test_main_text_reports_hosts_scanned(monkeypatch, capsys):
    findings = _sample_findings()

    async def fake_scan(self, targets, ports, **kwargs):
        self.last_hosts_scanned = 3
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    cli.main(["--target", "203.0.113.0/30", "--format", "text"])
    out = capsys.readouterr().out
    assert "3 host(s) scanned" in out.splitlines()[0]


def test_main_output_file_carries_hosts_scanned(monkeypatch, capsys, tmp_path):
    """The saved artefact (the whole point of the feature) carries the count."""
    findings = _sample_findings()

    async def fake_scan(self, targets, ports, **kwargs):
        self.last_hosts_scanned = 254
        return findings

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    out_path = tmp_path / "results.json"
    exit_code = cli.main(
        [
            "--target",
            "203.0.113.0/24",
            "--format",
            "json",
            "--output-file",
            str(out_path),
        ]
    )
    assert exit_code == 0
    assert capsys.readouterr().out == ""
    summary = json.loads(out_path.read_text(encoding="utf-8"))["summary"]
    assert summary["hosts_scanned"] == 254
