"""Tests for the scan engine: probing, matching, and auth-checking.

These tests use httpx.MockTransport so they run in any environment with no
network and no Docker. The Hikvision case (criterion 5) is the headline test.
"""

import asyncio

import httpx
import pytest

from hellhound.fingerprint import (
    AuthCheck,
    Credential,
    Fingerprint,
    MatchCriteria,
)
from hellhound.scanner import Scanner, extract_title


def run(coro):
    return asyncio.run(coro)


def hikvision_fingerprint() -> Fingerprint:
    return Fingerprint(
        id="hikvision-dvr",
        vendor="Hikvision",
        model_class="DVR / NVR / IP Camera",
        severity="critical",
        match=MatchCriteria(path="/", http_title="Hikvision"),
        credentials=[Credential("admin", "12345")],
        auth=AuthCheck(type="basic", path="/ISAPI/Security/userCheck"),
    )


def test_extract_title():
    assert extract_title("<html><head><title>Hikvision</title></head>") == "Hikvision"
    assert extract_title("<TITLE> RouterOS </TITLE>") == "RouterOS"
    assert extract_title("<html>no title here</html>") == ""


def make_hikvision_handler(*, accept_creds: bool):
    """Return a MockTransport handler emulating a Hikvision DVR.

    The landing page advertises the Hikvision title; the auth endpoint
    accepts admin/12345 (default creds) when ``accept_creds`` is True.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><head><title>Hikvision Network Camera</title></head><body>"
                "<a href='doc/page/login.asp'>login</a></body></html>",
            )
        if request.url.path == "/ISAPI/Security/userCheck":
            auth = request.headers.get("authorization", "")
            # httpx encodes basic auth; admin:12345 -> base64 'YWRtaW46MTIzNDU='
            if accept_creds and auth == "Basic YWRtaW46MTIzNDU=":
                return httpx.Response(200, text="<userCheck><statusValue>200</statusValue></userCheck>")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    return handler


def test_hikvision_default_creds_flagged():
    """Criterion 5: mock a Hikvision DVR default-creds login and assert hellhound
    flags the device AND the working credential pair."""
    transport = httpx.MockTransport(make_hikvision_handler(accept_creds=True))
    scanner = Scanner(
        fingerprints=[hikvision_fingerprint()],
        transport=transport,
    )

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Hikvision"
    assert finding.model_class == "DVR / NVR / IP Camera"
    assert finding.severity == "critical"
    assert finding.default_creds is True
    assert finding.matched_credential == Credential("admin", "12345")
    assert finding.host == "203.0.113.10"
    assert finding.port == 80
    assert finding.evidence  # non-empty human-readable evidence


def test_hikvision_matched_but_creds_rotated():
    """Device matches the fingerprint but rejects default creds -> matched, not flagged."""
    transport = httpx.MockTransport(make_hikvision_handler(accept_creds=False))
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.vendor == "Hikvision"
    assert finding.default_creds is False
    assert finding.matched_credential is None


def test_non_matching_host_yields_no_findings():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><head><title>Apache</title></head></html>")

    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))
    assert findings == []


def test_unreachable_host_yields_no_findings():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))
    assert findings == []


def test_form_auth_success_detection():
    """Form-based auth: success determined by status and absence of failure marker."""
    fp = Fingerprint(
        id="dahua-dvr",
        vendor="Dahua",
        model_class="DVR",
        severity="critical",
        match=MatchCriteria(path="/", body_contains="RPC2_Login"),
        credentials=[Credential("admin", "admin")],
        auth=AuthCheck(
            type="form",
            path="/RPC2_Login",
            method="POST",
            username_field="userName",
            password_field="password",
            success_status=(200,),
            failure_body_contains="error",
        ),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>RPC2_Login</body></html>")
        if request.url.path == "/RPC2_Login":
            body = request.content.decode()
            if "userName=admin" in body and "password=admin" in body:
                return httpx.Response(200, text='{"result":true}')
            return httpx.Response(200, text='{"result":false,"error":"bad creds"}')
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[fp], transport=transport)
    findings = run(scanner.scan_host("198.51.100.5", ports=[80]))

    assert len(findings) == 1
    assert findings[0].default_creds is True
    assert findings[0].matched_credential == Credential("admin", "admin")


def test_scan_targets_expands_cidr_and_dedupes():
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    hosts = scanner.expand_targets(["203.0.113.0/30", "203.0.113.0/30", "10.0.0.5"])
    # /30 yields 2 usable hosts (.1 and .2); plus the single host
    assert "203.0.113.1" in hosts
    assert "203.0.113.2" in hosts
    assert "10.0.0.5" in hosts
    # dedupe: no repeats
    assert len(hosts) == len(set(hosts))


def test_scan_targets_single_ip():
    scanner = Scanner(fingerprints=[], transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    assert scanner.expand_targets(["192.0.2.1"]) == ["192.0.2.1"]


def test_finding_to_dict_is_json_serializable():
    import json

    transport = httpx.MockTransport(make_hikvision_handler(accept_creds=True))
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)
    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))
    payload = [f.to_dict() for f in findings]
    serialized = json.dumps(payload)
    assert "Hikvision" in serialized
    loaded = json.loads(serialized)
    assert loaded[0]["default_creds"] is True
    assert loaded[0]["matched_credential"]["username"] == "admin"
