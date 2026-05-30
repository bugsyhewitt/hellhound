"""Mock-transport tests for the twenty-first Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
twenty-first expansion (Fortinet FortiNAC network access control appliance,
Drupal content management system, Joomla content management system
administrator portal, Liferay Portal / Digital Experience Platform, Kaseya VSA
remote monitoring and management server, PHP CGI handler exposed by an
internet-facing web server, Trend Micro Mobile Security enterprise management
server, and Veritas Backup Exec agent / web management console) — additional
internet-facing enterprise appliances, CMS platforms, RMM and backup servers
mass-exploited across the CISA Known Exploited Vulnerabilities (KEV) catalog.
Each test drives the real Scanner against an ``httpx.MockTransport`` emulating
the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche20.py``.
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


# ---------------------------------------------------------------- fortinac
def test_fortinet_fortinac_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>FortiNAC Administration</body></html>"
            )
        if request.url.path == "/login":
            if (
                form_field(request, "username") == "administrator"
                and form_field(request, "password") == ""
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Username or password is incorrect")
        return httpx.Response(404)

    findings = scan_one("fortinet-fortinac", handler)
    assert_flagged(
        findings,
        fingerprint_id="fortinet-fortinac",
        vendor="Fortinet",
        cred=Credential("administrator", ""),
    )


# ------------------------------------------------------------------ drupal
def test_drupal_cms_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Welcome</body></html>",
                headers={"X-Generator": "Drupal 10 (https://www.drupal.org)"},
            )
        if request.url.path == "/user/login":
            if (
                form_field(request, "name") == "admin"
                and form_field(request, "pass") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Unrecognized username or password.")
        return httpx.Response(404)

    findings = scan_one("drupal-cms", handler)
    assert_flagged(
        findings,
        fingerprint_id="drupal-cms",
        vendor="Drupal Association",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------------ joomla
def test_joomla_cms_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Joomla! Administration Login</body></html>"
            )
        if request.url.path == "/administrator/index.php":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "passwd") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Username and password do not match or you do not have an account yet")
        return httpx.Response(404)

    findings = scan_one("joomla-cms", handler)
    assert_flagged(
        findings,
        fingerprint_id="joomla-cms",
        vendor="Open Source Matters",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------------- liferay
def test_liferay_portal_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Liferay Portal</body></html>"
            )
        if request.url.path == "/c/portal/login":
            if (
                form_field(request, "login") == "test@liferay.com"
                and form_field(request, "password") == "test"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Authentication failed")
        return httpx.Response(404)

    findings = scan_one("liferay-portal", handler)
    assert_flagged(
        findings,
        fingerprint_id="liferay-portal",
        vendor="Liferay",
        cred=Credential("test@liferay.com", "test"),
    )


# ------------------------------------------------------------------ kaseya
def test_kaseya_vsa_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Kaseya VSA Login</body></html>"
            )
        if request.url.path == "/LoginRpt.asp":
            if (
                form_field(request, "vsaUser") == "kadmin"
                and form_field(request, "vsaPass") == "kaseya"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Logon failed")
        return httpx.Response(404)

    findings = scan_one("kaseya-vsa", handler)
    assert_flagged(
        findings,
        fingerprint_id="kaseya-vsa",
        vendor="Kaseya",
        cred=Credential("kadmin", "kaseya"),
    )


# ---------------------------------------------------------------- php-cgi
def test_php_cgi_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>It works!</body></html>",
                headers={"X-Powered-By": "PHP/8.3.7"},
            )
        if request.url.path == "/phpmyadmin/index.php":
            if (
                form_field(request, "pma_username") == "admin"
                and form_field(request, "pma_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Cannot log in to the MySQL server")
        return httpx.Response(404)

    findings = scan_one("php-cgi-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="php-cgi-server",
        vendor="PHP Group",
        cred=Credential("admin", "admin"),
    )


# ---------------------------------------------------------- trend micro mdm
def test_trendmicro_mobile_security_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Trend Micro Mobile Security for Enterprise</body></html>",
            )
        if request.url.path == "/mdm/web/login":
            if (
                form_field(request, "account") == "root"
                and form_field(request, "password") == "mobilesecurity"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Account or password is incorrect")
        return httpx.Response(404)

    findings = scan_one("trendmicro-mobile-security", handler)
    assert_flagged(
        findings,
        fingerprint_id="trendmicro-mobile-security",
        vendor="Trend Micro",
        cred=Credential("root", "mobilesecurity"),
    )


# ------------------------------------------------------------ backup exec
def test_veritas_backup_exec_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Veritas Backup Exec Console</body></html>"
            )
        if request.url.path == "/bemcli/login":
            if (
                form_field(request, "username") == "BEAdmin"
                and form_field(request, "password") == "backup"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Logon failed")
        return httpx.Response(404)

    findings = scan_one("veritas-backup-exec", handler)
    assert_flagged(
        findings,
        fingerprint_id="veritas-backup-exec",
        vendor="Veritas",
        cred=Credential("BEAdmin", "backup"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche21_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-21 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Joomla form-auth entry: the device advertises its fingerprint on
    the administrator landing page but the auth endpoint rejects the default
    credentials (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Joomla! Administration Login</body></html>"
            )
        if request.url.path == "/administrator/index.php":
            return httpx.Response(
                200, text="Username and password do not match or you do not have an account yet"
            )
        return httpx.Response(404)

    findings = scan_one("joomla-cms", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "joomla-cms"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
