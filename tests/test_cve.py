"""Tests for the per-finding CVE cross-reference feature.

Covers the fingerprint schema (optional ``cve`` field), Finding serialisation,
and the three output formats (json / csv / text) carrying CVE references.
"""

import csv
import io
import json

from hellhound import cli
from hellhound.fingerprint import Credential, load_fingerprint_set, load_fingerprints_from_dict
from hellhound.scanner import Finding


# ---------------------------------------------------------------- schema loading


def test_fingerprint_cve_defaults_to_empty():
    """A fingerprint with no cve field loads with an empty tuple."""
    data = {
        "fingerprints": [
            {
                "id": "no-cve",
                "vendor": "Acme",
                "model_class": "Router",
                "severity": "medium",
                "match": {"http_title": "Acme"},
                "default_credentials": [{"username": "admin", "password": "admin"}],
                "auth": {"type": "basic", "path": "/"},
            }
        ]
    }
    fp = load_fingerprints_from_dict(data)[0]
    assert fp.cve == ()


def test_fingerprint_cve_list_is_loaded():
    data = {
        "fingerprints": [
            {
                "id": "with-cve",
                "vendor": "Acme",
                "model_class": "AP",
                "severity": "critical",
                "match": {"http_title": "Acme"},
                "default_credentials": [{"username": "admin", "password": "x"}],
                "auth": {"type": "basic", "path": "/"},
                "cve": ["CVE-2025-37103", "CVE-2024-6047"],
            }
        ]
    }
    fp = load_fingerprints_from_dict(data)[0]
    assert fp.cve == ("CVE-2025-37103", "CVE-2024-6047")


def test_fingerprint_cve_accepts_single_string():
    data = {
        "fingerprints": [
            {
                "id": "single-cve",
                "vendor": "Acme",
                "model_class": "DVR",
                "severity": "high",
                "match": {"http_title": "Acme"},
                "default_credentials": [{"username": "admin", "password": "admin"}],
                "auth": {"type": "basic", "path": "/"},
                "cve": "CVE-2024-7921",
            }
        ]
    }
    fp = load_fingerprints_from_dict(data)[0]
    assert fp.cve == ("CVE-2024-7921",)


def test_fingerprint_cve_drops_blank_entries():
    data = {
        "fingerprints": [
            {
                "id": "blank-cve",
                "vendor": "Acme",
                "model_class": "DVR",
                "severity": "high",
                "match": {"http_title": "Acme"},
                "default_credentials": [{"username": "admin", "password": "admin"}],
                "auth": {"type": "basic", "path": "/"},
                "cve": ["CVE-2024-7921", "", "  "],
            }
        ]
    }
    fp = load_fingerprints_from_dict(data)[0]
    assert fp.cve == ("CVE-2024-7921",)


def test_bundled_database_backfills_known_cves():
    """The default set carries CVEs on the entries documented in POST_V01."""
    fps = load_fingerprint_set("default")
    by_id = {fp.id: fp for fp in fps}

    assert "CVE-2025-37103" in by_id["aruba-instant-on"].cve
    assert "CVE-2024-6047" in by_id["geovision-dvr"].cve
    assert "CVE-2024-11120" in by_id["geovision-dvr"].cve
    assert "CVE-2024-7921" in by_id["avtech-dvr"].cve

    # an entry with no known CVE stays empty
    assert by_id["hikvision-dvr"].cve == ()


# ---------------------------------------------------------------- Finding serialisation


def _finding_with_cve() -> Finding:
    return Finding(
        host="203.0.113.20",
        port=443,
        scheme="https",
        url="https://203.0.113.20:443/",
        fingerprint_id="aruba-instant-on",
        vendor="HPE Aruba",
        model_class="Enterprise access point",
        severity="critical",
        default_creds=True,
        matched_credential=Credential("admin", "default123"),
        evidence="default creds authenticated",
        cve=["CVE-2025-37103"],
    )


def _finding_without_cve() -> Finding:
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


def test_finding_to_dict_includes_cve_list():
    data = _finding_with_cve().to_dict()
    assert data["cve"] == ["CVE-2025-37103"]


def test_finding_default_cve_is_empty_list():
    data = _finding_without_cve().to_dict()
    assert data["cve"] == []


# ---------------------------------------------------------------- output formats


def test_json_output_carries_cve():
    out = cli.format_output([_finding_with_cve()], "json")
    parsed = json.loads(out)
    assert parsed["findings"][0]["cve"] == ["CVE-2025-37103"]


def test_csv_output_has_cve_column():
    out = cli.format_output([_finding_with_cve(), _finding_without_cve()], "csv")
    rows = list(csv.reader(io.StringIO(out)))
    assert "cve" in rows[0]
    record = dict(zip(rows[0], rows[1]))
    assert record["cve"] == "CVE-2025-37103"
    # finding without CVE has an empty cell
    record2 = dict(zip(rows[0], rows[2]))
    assert record2["cve"] == ""


def test_csv_joins_multiple_cves_with_semicolon():
    finding = _finding_with_cve()
    finding.cve = ["CVE-2024-6047", "CVE-2024-11120"]
    out = cli.format_output([finding], "csv")
    rows = list(csv.reader(io.StringIO(out)))
    record = dict(zip(rows[0], rows[1]))
    assert record["cve"] == "CVE-2024-6047;CVE-2024-11120"


def test_text_output_mentions_cve_when_present():
    out = cli.format_output([_finding_with_cve()], "text")
    assert "CVE-2025-37103" in out


def test_text_output_omits_cve_line_when_absent():
    out = cli.format_output([_finding_without_cve()], "text")
    assert "cve:" not in out
