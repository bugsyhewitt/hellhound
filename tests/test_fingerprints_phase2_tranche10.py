"""Mock-transport tests for the tenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
tenth expansion (Ivanti EPMM/MobileIron, ownCloud, Acronis Cyber Infrastructure,
Qlik Sense, Zyxel NAS, HPE OneView, Commvault Command Center, SysAid) —
internet-facing enterprise appliances, gateways and management consoles
mass-exploited across the 2023-2025 CISA KEV / ransomware landscape. Each test
drives the real Scanner against an ``httpx.MockTransport`` emulating the target
and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche9.py``.
"""

import asyncio

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


# ----------------------------------------------------------------- ivanti epmm
def test_ivanti_epmm_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>MobileIron Core admin portal</body></html>")
        if request.url.path == "/mifs/j_spring_security_check":
            if (
                form_field(request, "j_username") == "admin"
                and form_field(request, "j_password") == "changeme"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="login error")
        return httpx.Response(404)

    findings = scan_one("ivanti-epmm", handler)
    assert_flagged(
        findings,
        fingerprint_id="ivanti-epmm",
        vendor="Ivanti",
        cred=Credential("admin", "changeme"),
    )


# --------------------------------------------------------------- owncloud server
def test_owncloud_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>ownCloud file sync</body></html>")
        if request.url.path == "/index.php/login":
            if form_field(request, "user") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="wrong credentials")
        return httpx.Response(404)

    findings = scan_one("owncloud-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="owncloud-server",
        vendor="ownCloud",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------- acronis cyber infrastructure
def test_acronis_cyber_infrastructure_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Acronis Cyber Infrastructure</body></html>")
        if request.url.path == "/api/v2/login":
            if form_field(request, "username") == "root" and form_field(request, "password") == "default":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("acronis-cyber-infrastructure", handler)
    assert_flagged(
        findings,
        fingerprint_id="acronis-cyber-infrastructure",
        vendor="Acronis",
        cred=Credential("root", "default"),
    )


# ------------------------------------------------------------------- qlik sense
def test_qlik_sense_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Qlik Sense Enterprise hub</body></html>")
        if request.url.path == "/internal_forms_authentication/":
            if (
                form_field(request, "username") == "administrator"
                and form_field(request, "pwd") == "administrator"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="login failed")
        return httpx.Response(404)

    findings = scan_one("qlik-sense", handler)
    assert_flagged(
        findings,
        fingerprint_id="qlik-sense",
        vendor="Qlik",
        cred=Credential("administrator", "administrator"),
    )


# ------------------------------------------------------------------- zyxel nas
def test_zyxel_nas_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>NAS Login</body></html>")
        if request.url.path == "/cgi-bin/login.cgi":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "1234":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("zyxel-nas", handler)
    assert_flagged(
        findings,
        fingerprint_id="zyxel-nas",
        vendor="Zyxel",
        cred=Credential("admin", "1234"),
    )


# ------------------------------------------------------------------ hpe oneview
def test_hpe_oneview_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>HPE OneView</body></html>")
        if request.url.path == "/rest/login-sessions":
            if (
                form_field(request, "userName") == "Administrator"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("hpe-oneview", handler)
    assert_flagged(
        findings,
        fingerprint_id="hpe-oneview",
        vendor="HPE",
        cred=Credential("Administrator", "admin"),
    )


# ------------------------------------------------------ commvault command center
def test_commvault_command_center_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Command Center login</body></html>")
        if request.url.path == "/commandcenter/api/Login":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("commvault-command-center", handler)
    assert_flagged(
        findings,
        fingerprint_id="commvault-command-center",
        vendor="Commvault",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------------ sysaid server
def test_sysaid_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>SysAid Help Desk</body></html>")
        if request.url.path == "/enteradmin.htm":
            if (
                form_field(request, "userName") == "administrator"
                and form_field(request, "password") == "administrator"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("sysaid-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="sysaid-server",
        vendor="SysAid",
        cred=Credential("administrator", "administrator"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche10_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-10 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the ownCloud form-auth entry: the device advertises its fingerprint on
    the landing page but the login endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>ownCloud file sync</body></html>")
        if request.url.path == "/index.php/login":
            return httpx.Response(200, text="wrong credentials")  # always reject
        return httpx.Response(404)

    findings = scan_one("owncloud-server", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "owncloud-server"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
