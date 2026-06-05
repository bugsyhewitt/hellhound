"""Mock-transport tests for the twenty-fourth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in
the twenty-fourth expansion (Icinga2 Web network monitoring interface,
Graylog centralized log management server, Checkmk IT infrastructure
monitoring server, Pandora FMS network monitoring server, LibreNMS network
monitoring server, OpenNMS Horizon network management platform, OTRS IT
service management help-desk, and ManageEngine OpManager network performance
monitoring server) — additional internet-facing monitoring, log-management,
IT-service-management, and network-management servers with entries in the
CISA Known Exploited Vulnerabilities (KEV) catalog or mass-exploitation
records from 2022–2024. Each test drives the real Scanner against an
``httpx.MockTransport`` emulating the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for
the new entries. Mirrors the conventions in
``test_fingerprints_phase2_tranche23.py``.
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
    return next(f for f in BUNDLED if f.id == fingerprint_id)


def scan_one(fingerprint_id: str, handler):
    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[fp(fingerprint_id)], transport=transport)
    return run(scanner.scan_host("203.0.113.99", ports=[80]))


def form_field(request: httpx.Request, field: str) -> str:
    from urllib.parse import parse_qs

    body = request.content.decode()
    values = parse_qs(body).get(field, [])
    return values[0] if values else ""


def basic_creds(request: httpx.Request):
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return None, None
    raw = base64.b64decode(header.split(" ", 1)[1]).decode()
    user, _, pw = raw.partition(":")
    return user, pw


def assert_flagged(findings, *, fingerprint_id: str, vendor: str, cred: Credential):
    assert len(findings) == 1, f"expected exactly one finding, got {findings}"
    finding = findings[0]
    assert finding.fingerprint_id == fingerprint_id
    assert finding.vendor == vendor
    assert finding.default_creds is True
    assert finding.matched_credential == cred
    assert finding.evidence


# ------------------------------------------------------------- icinga2
def test_icinga2_web_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Icinga Web 2</body></html>"
            )
        if request.url.path == "/icingaweb2/authentication/login":
            if (
                form_field(request, "username") == "icingaadmin"
                and form_field(request, "password") == "icinga"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Incorrect username or password")
        return httpx.Response(404)

    findings = scan_one("icinga2-web", handler)
    assert_flagged(
        findings,
        fingerprint_id="icinga2-web",
        vendor="Icinga GmbH",
        cred=Credential("icingaadmin", "icinga"),
    )


# ----------------------------------------------------------- graylog
def test_graylog_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Graylog</body></html>"
            )
        if request.url.path == "/api/system/sessions":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text='{"session_id":"tok"}')
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("graylog-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="graylog-server",
        vendor="Graylog Inc.",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------- checkmk
def test_checkmk_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Checkmk</body></html>"
            )
        if request.url.path == "/check_mk/login.py":
            if (
                form_field(request, "_username") == "cmkadmin"
                and form_field(request, "_password") == "cmkadmin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("checkmk-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="checkmk-server",
        vendor="tribe29 GmbH",
        cred=Credential("cmkadmin", "cmkadmin"),
    )


# --------------------------------------------------------- pandora fms
def test_pandora_fms_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Pandora FMS</body></html>"
            )
        if request.url.path == "/pandora_console/index.php":
            if (
                form_field(request, "nick") == "admin"
                and form_field(request, "pass") == "pandora"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Login error")
        return httpx.Response(404)

    findings = scan_one("pandora-fms", handler)
    assert_flagged(
        findings,
        fingerprint_id="pandora-fms",
        vendor="PandoraFMS",
        cred=Credential("admin", "pandora"),
    )


# ---------------------------------------------------------- librenms
def test_librenms_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>LibreNMS</body></html>"
            )
        if request.url.path == "/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="These credentials do not match")
        return httpx.Response(404)

    findings = scan_one("librenms-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="librenms-server",
        vendor="LibreNMS",
        cred=Credential("admin", "admin"),
    )


# ---------------------------------------------------------- opennms
def test_opennms_horizon_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>OpenNMS</body></html>"
            )
        if request.url.path == "/opennms/j_spring_security_check":
            if (
                form_field(request, "j_username") == "admin"
                and form_field(request, "j_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Your login attempt was not successful")
        return httpx.Response(404)

    findings = scan_one("opennms-horizon", handler)
    assert_flagged(
        findings,
        fingerprint_id="opennms-horizon",
        vendor="OpenNMS Group",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------------- otrs
def test_otrs_helpdesk_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>OTRS</body></html>"
            )
        if request.url.path == "/otrs/index.pl":
            if (
                form_field(request, "User") == "root@localhost"
                and form_field(request, "Password") == "root"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Login failed")
        return httpx.Response(404)

    findings = scan_one("otrs-helpdesk", handler)
    assert_flagged(
        findings,
        fingerprint_id="otrs-helpdesk",
        vendor="OTRS AG",
        cred=Credential("root@localhost", "root"),
    )


# --------------------------------------------------- opmanager
def test_manageengine_opmanager_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>OpManager</body></html>"
            )
        if request.url.path == "/apiclient/ember/index.jsp":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid username or password")
        return httpx.Response(404)

    findings = scan_one("manageengine-opmanager", handler)
    assert_flagged(
        findings,
        fingerprint_id="manageengine-opmanager",
        vendor="Zoho Corporation",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------- matched-but-rotated guard
def test_tranche24_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-24 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real.

    Uses the Graylog form-auth entry: the device advertises its fingerprint on
    the landing page but the auth endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Graylog</body></html>"
            )
        if request.url.path == "/api/system/sessions":
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("graylog-server", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "graylog-server"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
