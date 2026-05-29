"""Mock-transport tests for the fifth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
fifth expansion (Barracuda ESG, Cisco IOS XE web UI, Progress MOVEit Transfer,
Progress Telerik, Atlassian Confluence, Ivanti Connect Secure, Fortinet
FortiGate, SonicWall SMA) — enterprise edge appliances and internet-facing
servers from the 2023-2025 KEV / mass-exploitation lists. Each test drives the
real Scanner against an ``httpx.MockTransport`` emulating the target device and
asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche4.py``.
"""

import asyncio
import base64

import httpx

from hellhound.fingerprint import Credential, load_fingerprint_set
from hellhound.scanner import Scanner


def run(coro):
    return asyncio.run(coro)


BUNDLED = load_fingerprint_set("default")


def fp(fingerprint_id: str):
    """Return the single bundled fingerprint with the given id."""
    return next(f for f in BUNDLED if f.id == fingerprint_id)


def scan_one(fingerprint_id: str, handler):
    """Scan one mock host against a single bundled fingerprint."""
    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[fp(fingerprint_id)], transport=transport)
    return run(scanner.scan_host("203.0.113.99", ports=[80]))


def basic_creds(request: httpx.Request) -> tuple[str, str] | None:
    """Decode an HTTP Basic Authorization header to (user, pass), or None."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
    except Exception:  # pragma: no cover - malformed header
        return None
    user, _, pwd = decoded.partition(":")
    return user, pwd


def form_field(request: httpx.Request, field: str) -> str:
    """Read a urlencoded form field value out of a POST body."""
    from urllib.parse import parse_qs

    body = request.content.decode()
    values = parse_qs(body).get(field, [])
    return values[0] if values else ""


def assert_flagged(findings, *, fingerprint_id: str, vendor: str, cred: Credential):
    assert len(findings) == 1, f"expected exactly one finding, got {findings}"
    finding = findings[0]
    assert finding.fingerprint_id == fingerprint_id
    assert finding.vendor == vendor
    assert finding.default_creds is True
    assert finding.matched_credential == cred
    assert finding.evidence


# ------------------------------------------------------------- barracuda esg
def test_barracuda_esg_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Barracuda Email Security Gateway</body></html>",
            )
        if request.url.path == "/cgi-mod/index.cgi":
            if form_field(request, "user") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("barracuda-esg", handler)
    assert_flagged(findings, fingerprint_id="barracuda-esg", vendor="Barracuda", cred=Credential("admin", "admin"))


# ----------------------------------------------------------- cisco ios xe webui
def test_cisco_ios_xe_webui_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><script src="/webui/index.html"></script></body></html>',
            )
        if request.url.path == "/webui/login":
            if form_field(request, "user") == "cisco" and form_field(request, "password") == "cisco":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("cisco-ios-xe-webui", handler)
    assert_flagged(
        findings,
        fingerprint_id="cisco-ios-xe-webui",
        vendor="Cisco",
        cred=Credential("cisco", "cisco"),
    )


# ----------------------------------------------------------- moveit transfer
def test_moveit_transfer_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>MOVEit Transfer</title></head></html>")
        if request.url.path == "/api/v1/token":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text='{"access_token":"x"}')
            return httpx.Response(200, text='{"error":"invalid_grant"}')
        return httpx.Response(404)

    findings = scan_one("moveit-transfer", handler)
    assert_flagged(findings, fingerprint_id="moveit-transfer", vendor="Progress", cred=Credential("admin", "admin"))


# --------------------------------------------------------------- telerik ui
def test_telerik_ui_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Telerik Report Server</body></html>")
        if request.url.path == "/Account/Login":
            if form_field(request, "Username") == "admin" and form_field(request, "Password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("telerik-ui", handler)
    assert_flagged(findings, fingerprint_id="telerik-ui", vendor="Progress", cred=Credential("admin", "admin"))


# --------------------------------------------------------- atlassian confluence
def test_atlassian_confluence_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>Dashboard - Confluence</title></head></html>")
        if request.url.path == "/dologin.action":
            if form_field(request, "os_username") == "admin" and form_field(request, "os_password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("atlassian-confluence", handler)
    assert_flagged(
        findings,
        fingerprint_id="atlassian-confluence",
        vendor="Atlassian",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------- ivanti connect secure
def test_ivanti_connect_secure_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><a href="/dana-na/auth/url_default/welcome.cgi">login</a></body></html>',
            )
        if request.url.path == "/dana-na/auth/url_admin/login.cgi":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("ivanti-connect-secure", handler)
    assert_flagged(
        findings,
        fingerprint_id="ivanti-connect-secure",
        vendor="Ivanti",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------- fortinet fortigate
def test_fortinet_fortigate_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><a href="/login?redir=%2F">login</a></body></html>',
            )
        if request.url.path == "/logincheck":
            if form_field(request, "username") == "admin" and form_field(request, "secretkey") == "":
                return httpx.Response(200, text="ret=ok")
            return httpx.Response(200, text="ret=error")
        return httpx.Response(404)

    findings = scan_one("fortinet-fortigate", handler)
    assert_flagged(
        findings,
        fingerprint_id="fortinet-fortigate",
        vendor="Fortinet",
        cred=Credential("admin", ""),
    )


# ------------------------------------------------------------- sonicwall sma
def test_sonicwall_sma_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>SonicWall Secure Mobile Access</body></html>")
        if request.url.path == "/__api__/v1/logon":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "password":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("sonicwall-sma", handler)
    assert_flagged(
        findings,
        fingerprint_id="sonicwall-sma",
        vendor="SonicWall",
        cred=Credential("admin", "password"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche5_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-5 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Confluence form-auth entry: the device advertises its fingerprint
    on the landing page but the login endpoint rejects the default credentials
    with a non-success status (i.e. they have been rotated)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>Dashboard - Confluence</title></head></html>")
        if request.url.path == "/dologin.action":
            return httpx.Response(401, text="error")  # always reject
        return httpx.Response(404)

    findings = scan_one("atlassian-confluence", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "atlassian-confluence"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
