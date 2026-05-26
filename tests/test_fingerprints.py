"""Tests for the fingerprint data model and database loading."""

from pathlib import Path

import pytest

from hellhound.fingerprint import (
    Credential,
    Fingerprint,
    MatchCriteria,
    load_fingerprint_set,
    load_fingerprints_from_dict,
)


def test_match_criteria_matches_http_title():
    crit = MatchCriteria(http_title="Hikvision")
    assert crit.matches(status=200, title="Hikvision Network Camera", body="", headers={})


def test_match_criteria_title_is_case_insensitive_substring():
    crit = MatchCriteria(http_title="hikvision")
    assert crit.matches(status=200, title="HIKVISION DVR", body="", headers={})


def test_match_criteria_no_match_when_title_absent():
    crit = MatchCriteria(http_title="Hikvision")
    assert not crit.matches(status=200, title="Some Other Router", body="", headers={})


def test_match_criteria_matches_body_contains():
    crit = MatchCriteria(body_contains="doc/page/login.asp")
    assert crit.matches(status=200, title="", body="<a href=doc/page/login.asp>", headers={})


def test_match_criteria_matches_header():
    crit = MatchCriteria(header_contains={"server": "RouterOS"})
    assert crit.matches(status=200, title="", body="", headers={"server": "Mikrotik RouterOS"})


def test_match_criteria_header_match_is_case_insensitive_on_name():
    crit = MatchCriteria(header_contains={"Server": "RouterOS"})
    assert crit.matches(status=200, title="", body="", headers={"server": "RouterOS v6"})


def test_match_criteria_requires_all_criteria():
    crit = MatchCriteria(http_title="Hikvision", body_contains="needle")
    # title matches but body does not -> no match
    assert not crit.matches(status=200, title="Hikvision", body="haystack", headers={})


def test_match_criteria_status_code_constraint():
    crit = MatchCriteria(http_title="Login", status_code=401)
    assert crit.matches(status=401, title="Login", body="", headers={})
    assert not crit.matches(status=200, title="Login", body="", headers={})


def test_empty_criteria_never_matches():
    # A fingerprint with no positive criteria must not match everything.
    crit = MatchCriteria()
    assert not crit.matches(status=200, title="anything", body="anything", headers={})


def test_load_fingerprints_from_dict_builds_fingerprint():
    data = {
        "fingerprints": [
            {
                "id": "hikvision-dvr",
                "vendor": "Hikvision",
                "model_class": "DVR/NVR/IP Camera",
                "severity": "critical",
                "match": {"http_title": "Hikvision", "path": "/"},
                "default_credentials": [
                    {"username": "admin", "password": "12345"},
                ],
                "auth": {"type": "basic", "path": "/ISAPI/Security/userCheck"},
            }
        ]
    }
    fps = load_fingerprints_from_dict(data)
    assert len(fps) == 1
    fp = fps[0]
    assert isinstance(fp, Fingerprint)
    assert fp.id == "hikvision-dvr"
    assert fp.vendor == "Hikvision"
    assert fp.severity == "critical"
    assert fp.credentials == [Credential("admin", "12345")]
    assert fp.auth.type == "basic"
    assert fp.auth.path == "/ISAPI/Security/userCheck"


def test_load_fingerprint_set_reads_bundled_database():
    fps = load_fingerprint_set("default")
    assert len(fps) >= 10, "v0.1 requires at least 10 fingerprints"


def test_bundled_database_entries_are_well_formed():
    fps = load_fingerprint_set("default")
    seen_ids = set()
    for fp in fps:
        assert fp.id, "every fingerprint needs an id"
        assert fp.id not in seen_ids, f"duplicate fingerprint id: {fp.id}"
        seen_ids.add(fp.id)
        assert fp.vendor, f"{fp.id} missing vendor"
        assert fp.model_class, f"{fp.id} missing model_class"
        assert fp.severity in {"low", "medium", "high", "critical"}, f"{fp.id} bad severity"
        assert fp.credentials, f"{fp.id} must have at least one default credential"
        assert fp.match.is_meaningful(), f"{fp.id} match criteria must be meaningful"


def test_bundled_database_includes_expected_vendors():
    fps = load_fingerprint_set("default")
    vendors = {fp.vendor.lower() for fp in fps}
    for expected in ("hikvision", "dahua", "mikrotik", "ubiquiti"):
        assert any(expected in v for v in vendors), f"expected a {expected} fingerprint"


def test_load_unknown_fingerprint_set_raises():
    with pytest.raises(FileNotFoundError):
        load_fingerprint_set("does-not-exist")


def test_hikvision_fingerprint_has_known_default_creds():
    fps = load_fingerprint_set("default")
    hik = next(fp for fp in fps if "hikvision" in fp.id.lower())
    assert Credential("admin", "12345") in hik.credentials


def test_fingerprints_dir_default_path_exists():
    fps_dir = Path(__file__).resolve().parents[1] / "hellhound" / "fingerprints"
    assert (fps_dir / "default.yaml").is_file()
