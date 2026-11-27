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


# ================================================================ Additional Scanner tests

from hellhound.scanner import Finding, ScanProgress  # noqa: E402


def dahua_fingerprint() -> Fingerprint:
    return Fingerprint(
        id="dahua-dvr",
        vendor="Dahua",
        model_class="DVR",
        severity="high",
        match=MatchCriteria(body_contains="RPC2_Login"),
        credentials=[Credential("admin", "admin")],
        auth=AuthCheck(
            type="form",
            path="/RPC2_Login",
            username_field="userName",
            password_field="password",
            success_status=(200,),
            failure_body_contains="error",
        ),
    )


def test_scan_host_https_port_uses_https_scheme():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<title>Hikvision</title>")
        return httpx.Response(401)

    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)
    findings = run(scanner.scan_host("192.0.2.1", ports=[443]))
    assert len(findings) == 1
    assert findings[0].scheme == "https"
    assert findings[0].port == 443


def test_scan_host_http_port_uses_http_scheme():
    transport = httpx.MockTransport(make_hikvision_handler(accept_creds=True))
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)
    findings = run(scanner.scan_host("192.0.2.1", ports=[80]))
    assert findings[0].scheme == "http"


def test_multiple_fingerprints_matches_correct_one():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<title>Hikvision Network Camera</title>")
        return httpx.Response(401)

    transport = httpx.MockTransport(handler)
    scanner = Scanner(
        fingerprints=[dahua_fingerprint(), hikvision_fingerprint()],
        transport=transport,
    )
    findings = run(scanner.scan_host("10.0.0.1", ports=[80]))
    # Only hikvision should match
    assert len(findings) == 1
    assert findings[0].vendor == "Hikvision"


def test_multiple_fingerprints_all_matching_devices_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            # Both fingerprints match: title for Hikvision, body for Dahua
            return httpx.Response(
                200,
                html="<html><head><title>Hikvision</title></head><body>RPC2_Login</body></html>",
            )
        return httpx.Response(200)

    hik = hikvision_fingerprint()
    # Create a second fingerprint that also matches based on body
    dahua_match_body = Fingerprint(
        id="dahua-match",
        vendor="Dahua",
        model_class="DVR",
        severity="high",
        match=MatchCriteria(body_contains="RPC2_Login"),
        credentials=[Credential("admin", "admin")],
        auth=AuthCheck(type="form", path="/RPC2_Login", success_status=(200,)),
    )
    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[hik, dahua_match_body], transport=transport)
    findings = run(scanner.scan_host("10.0.0.1", ports=[80]))
    assert len(findings) == 2


def test_scan_progress_callback_invoked():
    transport = httpx.MockTransport(make_hikvision_handler(accept_creds=True))
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    progress_calls = []

    def callback(progress: ScanProgress) -> None:
        progress_calls.append(progress)

    run(scanner.scan(["192.0.2.1"], [80], progress_callback=callback))
    assert len(progress_calls) == 1
    assert progress_calls[0].hosts_done == 1
    assert progress_calls[0].hosts_total == 1
    assert progress_calls[0].findings_with_default_creds == 1


def test_scan_progress_callback_counts_hosts_total():
    transport = httpx.MockTransport(lambda r: httpx.Response(404))
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    totals = []

    def callback(p: ScanProgress) -> None:
        totals.append(p.hosts_total)

    run(scanner.scan(["192.0.2.0/30"], [80], progress_callback=callback))
    # /30 has 2 usable hosts
    assert all(t == 2 for t in totals)


def test_last_hosts_scanned_set_after_scan():
    transport = httpx.MockTransport(lambda r: httpx.Response(404))
    scanner = Scanner(fingerprints=[], transport=transport)
    run(scanner.scan(["192.0.2.0/30"], [80]))
    assert scanner.last_hosts_scanned == 2


def test_last_hosts_scanned_excludes_filtered_hosts():
    transport = httpx.MockTransport(lambda r: httpx.Response(404))
    scanner = Scanner(fingerprints=[], transport=transport)
    import ipaddress
    exclusions = [ipaddress.ip_network("192.0.2.1/32")]
    run(scanner.scan(["192.0.2.0/30"], [80], exclusions=exclusions))
    assert scanner.last_hosts_scanned == 1  # 2 hosts minus the excluded one


def test_is_excluded_ip_in_network():
    import ipaddress
    nets = [ipaddress.ip_network("10.0.0.0/8")]
    assert Scanner.is_excluded("10.1.2.3", nets)


def test_is_excluded_ip_outside_network():
    import ipaddress
    nets = [ipaddress.ip_network("10.0.0.0/8")]
    assert not Scanner.is_excluded("192.168.1.1", nets)


def test_is_excluded_hostname_never_excluded():
    import ipaddress
    nets = [ipaddress.ip_network("0.0.0.0/0")]
    assert not Scanner.is_excluded("example.com", nets)


def test_is_excluded_empty_exclusions():
    assert not Scanner.is_excluded("10.0.0.1", [])


def test_parse_exclusions_from_file(tmp_path):
    exclude_file = tmp_path / "exclusions.txt"
    exclude_file.write_text(
        "# comment\n"
        "10.0.0.1\n"
        "\n"
        "192.168.0.0/24\n"
    )
    exclusions = Scanner.parse_exclusions(exclude_file=str(exclude_file))
    assert len(exclusions) == 2


def test_parse_exclusions_combines_list_and_file(tmp_path):
    exclude_file = tmp_path / "ex.txt"
    exclude_file.write_text("172.16.0.0/12\n")
    exclusions = Scanner.parse_exclusions(
        exclude=["10.0.0.1"], exclude_file=str(exclude_file)
    )
    assert len(exclusions) == 2


def test_finding_cve_field_propagated():
    fp_with_cve = Fingerprint(
        id="cve-fp",
        vendor="Vendor",
        model_class="cam",
        severity="critical",
        match=MatchCriteria(http_title="Vendor"),
        credentials=[Credential("admin", "admin")],
        auth=AuthCheck(type="basic", path="/check"),
        cve=("CVE-2024-1234",),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<title>Vendor cam</title>")
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[fp_with_cve], transport=transport)
    findings = run(scanner.scan_host("10.0.0.1", ports=[80]))
    assert len(findings) == 1
    assert "CVE-2024-1234" in findings[0].cve


def test_scan_progress_no_findings_callback_counts_flagged_zero():
    transport = httpx.MockTransport(lambda r: httpx.Response(404))
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    calls = []

    def callback(p: ScanProgress) -> None:
        calls.append(p)

    run(scanner.scan(["192.0.2.1"], [80], progress_callback=callback))
    assert calls[-1].findings_with_default_creds == 0


def test_extract_title_multiline():
    body = "<html><head><title>\n  My Device\n</title></head></html>"
    assert extract_title(body) == "My Device"


def test_extract_title_case_insensitive_tag():
    assert extract_title("<TITLE>Router</TITLE>") == "Router"


def test_scan_host_multiple_ports_scans_all():
    checked_ports = []

    def handler(request: httpx.Request) -> httpx.Response:
        # httpx returns None for port 80 (default HTTP); treat None as 80
        port = request.url.port if request.url.port is not None else 80
        checked_ports.append(port)
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)
    run(scanner.scan_host("192.0.2.1", ports=[80, 8080]))
    assert 80 in checked_ports
    assert 8080 in checked_ports


def test_scan_progress_dataclass_attributes():
    p = ScanProgress(hosts_done=3, hosts_total=10, findings_with_default_creds=1)
    assert p.hosts_done == 3
    assert p.hosts_total == 10
    assert p.findings_with_default_creds == 1
