"""Mock-transport tests for the seventh Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
seventh expansion (Zoho ManageEngine, Citrix ShareFile, Apache OFBiz, Openfire
XMPP, SolarWinds Orion, Langflow, Apache Tomcat Manager, Cacti) — internet-facing
enterprise web applications and management consoles from the 2022-2025 CISA KEV /
mass-exploitation lists. Each test drives the real Scanner against an
``httpx.MockTransport`` emulating the target device and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche6.py``.
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


# ----------------------------------------------------------- zoho manageengine
def test_zoho_manageengine_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>ManageEngine ADSelfService Plus</body></html>",
            )
        if request.url.path == "/j_security_check":
            if form_field(request, "j_username") == "admin" and form_field(request, "j_password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("zoho-manageengine", handler)
    assert_flagged(
        findings,
        fingerprint_id="zoho-manageengine",
        vendor="Zoho",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------- citrix sharefile
def test_citrix_sharefile_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>Citrix ShareFile</title></head></html>")
        if request.url.path == "/auth/login":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "password":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("citrix-sharefile", handler)
    assert_flagged(
        findings,
        fingerprint_id="citrix-sharefile",
        vendor="Citrix",
        cred=Credential("admin", "password"),
    )


# --------------------------------------------------------------- apache ofbiz
def test_apache_ofbiz_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Apache OFBiz e-Business</body></html>")
        if request.url.path == "/webtools/control/login":
            if form_field(request, "USERNAME") == "admin" and form_field(request, "PASSWORD") == "ofbiz":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("apache-ofbiz", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-ofbiz",
        vendor="Apache",
        cred=Credential("admin", "ofbiz"),
    )


# --------------------------------------------------------------- openfire xmpp
def test_openfire_xmpp_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Openfire Admin Console</body></html>")
        if request.url.path == "/login.jsp":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("openfire-xmpp", handler)
    assert_flagged(
        findings,
        fingerprint_id="openfire-xmpp",
        vendor="Ignite Realtime",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------- solarwinds orion
def test_solarwinds_orion_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>SolarWinds Orion</title></head></html>")
        if request.url.path == "/Orion/Login.aspx":
            user = form_field(request, "ctl00$BodyContent$Username")
            pwd = form_field(request, "ctl00$BodyContent$Password")
            if user == "admin" and pwd == "":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("solarwinds-orion", handler)
    assert_flagged(
        findings,
        fingerprint_id="solarwinds-orion",
        vendor="SolarWinds",
        cred=Credential("admin", ""),
    )


# ----------------------------------------------------------------- langflow
def test_langflow_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Langflow workflow builder</body></html>")
        if request.url.path == "/api/v1/login":
            if form_field(request, "username") == "langflow" and form_field(request, "password") == "langflow":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("langflow", handler)
    assert_flagged(
        findings,
        fingerprint_id="langflow",
        vendor="Langflow",
        cred=Credential("langflow", "langflow"),
    )


# ----------------------------------------------------- apache tomcat manager
def test_apache_tomcat_manager_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Apache Tomcat/9.0</body></html>")
        if request.url.path == "/manager/html":
            creds = basic_creds(request)
            if creds == ("tomcat", "tomcat"):
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("apache-tomcat-manager", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-tomcat-manager",
        vendor="Apache",
        cred=Credential("tomcat", "tomcat"),
    )


# ------------------------------------------------------------------- cacti
def test_cacti_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        # Cacti's login page and login POST share path "/index.php"; the landing
        # page is "/". Distinguish the auth POST by the presence of form fields.
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>Cacti</title></head></html>")
        if request.url.path == "/index.php":
            if form_field(request, "login_username") == "admin" and form_field(request, "login_password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("cacti", handler)
    assert_flagged(
        findings,
        fingerprint_id="cacti",
        vendor="Cacti",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche7_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-7 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Cacti form-auth entry: the device advertises its fingerprint on the
    landing page but the login endpoint rejects the default credentials with a
    non-success status (i.e. they have been rotated)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>Cacti</title></head></html>")
        if request.url.path == "/index.php":
            return httpx.Response(401, text="error")  # always reject
        return httpx.Response(404)

    findings = scan_one("cacti", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "cacti"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
