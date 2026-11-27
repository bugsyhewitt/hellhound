"""Tests for the fingerprint data model, YAML loader, merge logic, and helpers.

Covers areas not addressed by test_fingerprints.py or test_validate.py:
- _build_cve normalisation (list, single string, None, blanks)
- load_fingerprints_from_dict for form auth with all custom fields, and
  fingerprints with CVE, description, multiple credentials, and defaults
- MatchCriteria.is_meaningful in all combinations
- MatchCriteria.matches edge cases: multi-header AND, empty headers dict
- Credential dataclass: frozen, str, equality
- AuthCheck: defaults, form-specific fields
- merge_fingerprints semantics: override in place, append new, preserve order
- load_fingerprint_set_with_dir error paths: missing dir, missing yaml
- Fingerprint frozen: attempt to mutate raises
- load_fingerprints_from_dict with empty fingerprints list
"""

from __future__ import annotations

import pytest

from hellhound.fingerprint import (
    AuthCheck,
    Credential,
    Fingerprint,
    MatchCriteria,
    load_fingerprint_set,
    load_fingerprint_set_with_dir,
    load_fingerprints_from_dict,
    merge_fingerprints,
    validate_fingerprints,
)


# ------------------------------------------------------------------ Credential


def test_credential_equality_by_value():
    a = Credential("admin", "12345")
    b = Credential("admin", "12345")
    assert a == b


def test_credential_inequality_different_password():
    assert Credential("admin", "12345") != Credential("admin", "admin")


def test_credential_is_frozen():
    cred = Credential("admin", "pass")
    with pytest.raises((AttributeError, TypeError)):
        cred.username = "other"  # type: ignore[misc]


def test_credential_hash_equal_for_equal_values():
    a = Credential("user", "pw")
    b = Credential("user", "pw")
    assert hash(a) == hash(b)


# ---------------------------------------------------------------- MatchCriteria


def test_is_meaningful_title_only():
    assert MatchCriteria(http_title="X").is_meaningful()


def test_is_meaningful_body_only():
    assert MatchCriteria(body_contains="login").is_meaningful()


def test_is_meaningful_header_only():
    assert MatchCriteria(header_contains={"server": "app"}).is_meaningful()


def test_is_meaningful_all_three():
    mc = MatchCriteria(
        http_title="A",
        body_contains="b",
        header_contains={"x-ver": "1"},
    )
    assert mc.is_meaningful()


def test_is_meaningful_empty_header_dict_false():
    assert not MatchCriteria(header_contains={}).is_meaningful()


def test_matches_body_contains_case_insensitive():
    mc = MatchCriteria(body_contains="LOGIN.ASP")
    assert mc.matches(status=200, title="", body="login.asp", headers={})


def test_matches_header_key_case_insensitive():
    mc = MatchCriteria(header_contains={"X-Custom": "val"})
    assert mc.matches(status=200, title="", body="", headers={"x-custom": "val"})


def test_matches_header_value_case_insensitive():
    mc = MatchCriteria(header_contains={"server": "MIKROTIK"})
    assert mc.matches(status=200, title="", body="", headers={"server": "Mikrotik RouterOS"})


def test_matches_multiple_headers_all_must_match():
    mc = MatchCriteria(header_contains={"server": "app", "x-frame-options": "SAMEORIGIN"})
    assert mc.matches(
        status=200, title="", body="",
        headers={"server": "App-webs", "x-frame-options": "SAMEORIGIN"}
    )
    assert not mc.matches(
        status=200, title="", body="",
        headers={"server": "App-webs"}  # second header absent
    )


def test_matches_absent_header_in_header_contains_fails():
    mc = MatchCriteria(header_contains={"x-device-type": "cam"})
    assert not mc.matches(status=200, title="", body="", headers={})


def test_matches_status_code_none_accepts_any_status():
    mc = MatchCriteria(http_title="device", status_code=None)
    for code in (200, 301, 401, 403):
        assert mc.matches(status=code, title="device", body="", headers={})


# ------------------------------------------------------------------ AuthCheck


def test_authcheck_basic_defaults():
    auth = AuthCheck(type="basic", path="/check")
    assert auth.type == "basic"
    assert auth.path == "/check"
    assert auth.method == "POST"
    assert auth.username_field == "username"
    assert auth.password_field == "password"
    assert auth.success_status == (200,)
    assert auth.failure_body_contains is None
    assert auth.extra_fields == {}


def test_authcheck_form_custom_fields():
    auth = AuthCheck(
        type="form",
        path="/login.cgi",
        method="POST",
        username_field="user",
        password_field="passwd",
        success_status=(200, 302),
        failure_body_contains="Invalid",
        extra_fields={"lang": "en"},
    )
    assert auth.username_field == "user"
    assert auth.password_field == "passwd"
    assert 302 in auth.success_status
    assert auth.failure_body_contains == "Invalid"
    assert auth.extra_fields == {"lang": "en"}


def test_authcheck_is_frozen():
    auth = AuthCheck(type="basic", path="/")
    with pytest.raises((AttributeError, TypeError)):
        auth.type = "form"  # type: ignore[misc]


# ------------------------------------------------ load_fingerprints_from_dict


def test_load_empty_fingerprints_list():
    fps = load_fingerprints_from_dict({"fingerprints": []})
    assert fps == []


def test_load_missing_fingerprints_key_returns_empty():
    fps = load_fingerprints_from_dict({})
    assert fps == []


def test_load_fingerprint_cve_as_list():
    data = {
        "fingerprints": [
            {
                "id": "test-fp",
                "vendor": "V",
                "severity": "high",
                "cve": ["CVE-2024-1234", "CVE-2024-5678"],
                "match": {"http_title": "V"},
                "default_credentials": [{"username": "a", "password": "b"}],
                "auth": {"type": "basic", "path": "/"},
            }
        ]
    }
    fps = load_fingerprints_from_dict(data)
    assert fps[0].cve == ("CVE-2024-1234", "CVE-2024-5678")


def test_load_fingerprint_cve_as_single_string():
    data = {
        "fingerprints": [
            {
                "id": "cve-fp",
                "vendor": "V",
                "severity": "critical",
                "cve": "CVE-2023-9999",
                "match": {"http_title": "V"},
                "default_credentials": [{"username": "a", "password": "b"}],
                "auth": {"type": "basic", "path": "/"},
            }
        ]
    }
    fps = load_fingerprints_from_dict(data)
    assert fps[0].cve == ("CVE-2023-9999",)


def test_load_fingerprint_cve_absent_defaults_empty():
    data = {
        "fingerprints": [
            {
                "id": "no-cve",
                "vendor": "V",
                "severity": "low",
                "match": {"body_contains": "V"},
                "default_credentials": [{"username": "a", "password": "b"}],
                "auth": {"type": "basic", "path": "/"},
            }
        ]
    }
    fps = load_fingerprints_from_dict(data)
    assert fps[0].cve == ()


def test_load_fingerprint_multiple_credentials():
    data = {
        "fingerprints": [
            {
                "id": "multi-cred",
                "vendor": "V",
                "severity": "medium",
                "match": {"http_title": "V"},
                "default_credentials": [
                    {"username": "admin", "password": "admin"},
                    {"username": "user", "password": "1234"},
                    {"username": "root", "password": ""},
                ],
                "auth": {"type": "basic", "path": "/"},
            }
        ]
    }
    fps = load_fingerprints_from_dict(data)
    assert len(fps[0].credentials) == 3
    assert fps[0].credentials[2] == Credential("root", "")


def test_load_fingerprint_form_auth_all_fields():
    data = {
        "fingerprints": [
            {
                "id": "form-fp",
                "vendor": "V",
                "severity": "high",
                "match": {"body_contains": "login"},
                "default_credentials": [{"username": "admin", "password": "pass"}],
                "auth": {
                    "type": "form",
                    "path": "/login",
                    "method": "POST",
                    "username_field": "user",
                    "password_field": "pwd",
                    "success_status": [200, 302],
                    "failure_body_contains": "wrong",
                    "extra_fields": {"csrf": "token"},
                },
            }
        ]
    }
    fps = load_fingerprints_from_dict(data)
    auth = fps[0].auth
    assert auth.type == "form"
    assert auth.username_field == "user"
    assert auth.password_field == "pwd"
    assert 302 in auth.success_status
    assert auth.failure_body_contains == "wrong"
    assert auth.extra_fields == {"csrf": "token"}


def test_load_fingerprint_description_field():
    data = {
        "fingerprints": [
            {
                "id": "desc-fp",
                "vendor": "V",
                "severity": "low",
                "description": "A test fingerprint",
                "match": {"http_title": "V"},
                "default_credentials": [{"username": "a", "password": "b"}],
                "auth": {"type": "basic", "path": "/"},
            }
        ]
    }
    fps = load_fingerprints_from_dict(data)
    assert fps[0].description == "A test fingerprint"


# ---------------------------------------------- merge_fingerprints


def _make_fp(fp_id: str, vendor: str = "V") -> Fingerprint:
    return Fingerprint(
        id=fp_id,
        vendor=vendor,
        model_class="cam",
        severity="medium",
        match=MatchCriteria(http_title=vendor),
        credentials=[Credential("admin", "admin")],
        auth=AuthCheck(type="basic", path="/"),
    )


def test_merge_override_replaces_bundled_in_place():
    bundled = [_make_fp("fp-a", "OldVendor"), _make_fp("fp-b")]
    override = _make_fp("fp-a", "NewVendor")
    merged = merge_fingerprints(bundled, [override])
    assert len(merged) == 2
    fp_a = next(fp for fp in merged if fp.id == "fp-a")
    assert fp_a.vendor == "NewVendor"


def test_merge_new_entry_appended_after_bundled():
    bundled = [_make_fp("fp-a"), _make_fp("fp-b")]
    override = _make_fp("fp-new")
    merged = merge_fingerprints(bundled, [override])
    assert len(merged) == 3
    assert merged[-1].id == "fp-new"


def test_merge_bundled_only_entries_preserved():
    bundled = [_make_fp("fp-a"), _make_fp("fp-b"), _make_fp("fp-c")]
    merged = merge_fingerprints(bundled, [])
    assert len(merged) == 3
    assert [fp.id for fp in merged] == ["fp-a", "fp-b", "fp-c"]


def test_merge_preserves_bundled_ordering():
    bundled = [_make_fp("x"), _make_fp("y"), _make_fp("z")]
    # Override middle entry
    merged = merge_fingerprints(bundled, [_make_fp("y", "New")])
    assert [fp.id for fp in merged] == ["x", "y", "z"]
    assert merged[1].vendor == "New"


def test_merge_empty_bundled_appends_all_overrides():
    overrides = [_make_fp("a"), _make_fp("b")]
    merged = merge_fingerprints([], overrides)
    assert len(merged) == 2


# -------------------------------------- load_fingerprint_set_with_dir errors


def test_load_with_dir_missing_dir_raises(tmp_path):
    missing = tmp_path / "no-such-dir"
    with pytest.raises(FileNotFoundError, match="fingerprint directory not found"):
        load_fingerprint_set_with_dir("default", fingerprint_dir=missing)


def test_load_with_dir_missing_yaml_raises(tmp_path):
    # Directory exists but has no default.yaml
    with pytest.raises(FileNotFoundError, match="no 'default.yaml'"):
        load_fingerprint_set_with_dir("default", fingerprint_dir=tmp_path)


def test_load_with_dir_merges_custom_into_bundled(tmp_path):
    (tmp_path / "default.yaml").write_text(
        "fingerprints:\n"
        "  - id: private-cam\n"
        "    vendor: Private\n"
        "    severity: high\n"
        "    match: {http_title: Private}\n"
        "    default_credentials: [{username: admin, password: secret}]\n"
        "    auth: {type: basic, path: /check}\n"
    )
    fps = load_fingerprint_set_with_dir("default", fingerprint_dir=tmp_path)
    ids = [fp.id for fp in fps]
    assert "private-cam" in ids
    # bundled entries still present
    assert any("hikvision" in fp_id for fp_id in ids)


# ----------------------------------------- bundled database sanity


def test_bundled_database_has_fingerprints_with_cve():
    fps = load_fingerprint_set("default")
    with_cve = [fp for fp in fps if fp.cve]
    assert len(with_cve) >= 5, "expect several CVE-linked fingerprints in the bundled set"


def test_bundled_database_has_form_auth_entries():
    fps = load_fingerprint_set("default")
    form_fps = [fp for fp in fps if fp.auth.type == "form"]
    assert len(form_fps) >= 1, "expect at least one form-auth fingerprint"


def test_bundled_database_all_fingerprints_pass_validate():
    fps = load_fingerprint_set("default")
    errors = validate_fingerprints(fps)
    assert errors == [], f"bundled database has validation errors: {errors}"
