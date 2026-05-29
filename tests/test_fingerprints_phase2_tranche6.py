"""Mock-transport tests for the sixth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
sixth expansion (Veeam Backup & Replication, Citrix NetScaler ADC/Gateway,
Progress WS_FTP Server, Adobe ColdFusion, ConnectWise ScreenConnect, GeoServer,
Roundcube webmail, PaperCut NG/MF) — internet-facing enterprise servers and
remote-access appliances from the 2023-2025 CISA KEV / mass-exploitation lists.
Each test drives the real Scanner against an ``httpx.MockTransport`` emulating
the target device and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche5.py``.
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


# --------------------------------------------------------------- veeam backup
def test_veeam_backup_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Veeam Backup Enterprise Manager</body></html>",
            )
        if request.url.path == "/api/sessionMngr/":
            if form_field(request, "username") == "administrator" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("veeam-backup", handler)
    assert_flagged(
        findings,
        fingerprint_id="veeam-backup",
        vendor="Veeam",
        cred=Credential("administrator", "admin"),
    )


# ----------------------------------------------------------- citrix netscaler
def test_citrix_netscaler_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><a href="/vpn/index.html">login</a></body></html>',
            )
        if request.url.path == "/nclogin":
            if form_field(request, "login") == "nsroot" and form_field(request, "passwd") == "nsroot":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("citrix-netscaler", handler)
    assert_flagged(
        findings,
        fingerprint_id="citrix-netscaler",
        vendor="Citrix",
        cred=Credential("nsroot", "nsroot"),
    )


# ----------------------------------------------------------- progress ws_ftp
def test_progress_wsftp_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>WS_FTP Server</title></head></html>")
        if request.url.path == "/SignIn":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("progress-wsftp", handler)
    assert_flagged(
        findings,
        fingerprint_id="progress-wsftp",
        vendor="Progress",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------- adobe coldfusion
def test_adobe_coldfusion_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><a href="/CFIDE/administrator/index.cfm">admin</a></body></html>',
            )
        if request.url.path == "/CFIDE/administrator/enter.cfm":
            if form_field(request, "cfadminUserId") == "admin" and form_field(request, "cfadminPassword") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("adobe-coldfusion", handler)
    assert_flagged(
        findings,
        fingerprint_id="adobe-coldfusion",
        vendor="Adobe",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------- connectwise screenconnect
def test_connectwise_screenconnect_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>ScreenConnect Management</body></html>")
        if request.url.path == "/Services/AuthenticationService.ashx/TryLogin":
            if form_field(request, "userName") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("connectwise-screenconnect", handler)
    assert_flagged(
        findings,
        fingerprint_id="connectwise-screenconnect",
        vendor="ConnectWise",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------------- geoserver
def test_geoserver_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>GeoServer Web Admin</title></head></html>")
        if request.url.path == "/geoserver/j_spring_security_check":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "geoserver":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("geoserver", handler)
    assert_flagged(
        findings,
        fingerprint_id="geoserver",
        vendor="GeoServer",
        cred=Credential("admin", "geoserver"),
    )


# --------------------------------------------------------- roundcube webmail
def test_roundcube_webmail_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        # The login endpoint and the landing page share path "/"; distinguish
        # them by the presence of the _task=login query the auth POST carries.
        if request.url.path == "/" and request.url.params.get("_task") == "login":
            if form_field(request, "_user") == "admin" and form_field(request, "_pass") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        if request.url.path == "/":
            return httpx.Response(200, html='<html><body class="roundcube">Webmail</body></html>')
        return httpx.Response(404)

    findings = scan_one("roundcube-webmail", handler)
    assert_flagged(
        findings,
        fingerprint_id="roundcube-webmail",
        vendor="Roundcube",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------- papercut ng
def test_papercut_ng_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>PaperCut MF Admin</body></html>")
        if request.url.path == "/app":
            if form_field(request, "usernameField") == "admin" and form_field(request, "passwordField") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("papercut-ng", handler)
    assert_flagged(
        findings,
        fingerprint_id="papercut-ng",
        vendor="PaperCut",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche6_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-6 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the GeoServer form-auth entry: the device advertises its fingerprint on
    the landing page but the login endpoint rejects the default credentials with
    a non-success status (i.e. they have been rotated)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>GeoServer Web Admin</title></head></html>")
        if request.url.path == "/geoserver/j_spring_security_check":
            return httpx.Response(401, text="error")  # always reject
        return httpx.Response(404)

    findings = scan_one("geoserver", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "geoserver"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
