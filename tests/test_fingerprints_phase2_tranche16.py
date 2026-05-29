"""Mock-transport tests for the sixteenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
sixteenth expansion (Fortinet FortiVoice unified-communications admin, SAP
NetWeaver Visual Composer, Sitecore Experience Platform CMS, the Wazuh security
platform, Craft CMS control panel, Gladinet CentreStack file-sharing portal,
Ivanti Endpoint Manager, and Mitel 6800/6900 SIP desk phones) — internet-facing
admin consoles, CMS control panels, file-sharing portals, SIEM dashboards and
device web UIs mass-exploited across the CISA Known Exploited Vulnerabilities
(KEV) catalog. Each test drives the real Scanner against an
``httpx.MockTransport`` emulating the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche15.py``.
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


def form_field(request: httpx.Request, field: str) -> str:
    """Read a urlencoded form field value out of a POST body."""
    from urllib.parse import parse_qs

    body = request.content.decode()
    values = parse_qs(body).get(field, [])
    return values[0] if values else ""


def basic_creds(request: httpx.Request):
    """Decode HTTP Basic credentials from a request, or (None, None)."""
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


# --------------------------------------------------------- fortinet fortivoice
def test_fortinet_fortivoice_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>FortiVoice Enterprise</body></html>"
            )
        if request.url.path == "/api/v1/AdminLogin":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == ""
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("fortinet-fortivoice", handler)
    assert_flagged(
        findings,
        fingerprint_id="fortinet-fortivoice",
        vendor="Fortinet",
        cred=Credential("admin", ""),
    )


# ------------------------------------------------------------- sap netweaver
def test_sap_netweaver_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>SAP NetWeaver Application Server</body></html>"
            )
        if request.url.path == "/irj/portal":
            if (
                form_field(request, "j_user") == "Administrator"
                and form_field(request, "j_password") == "welcome"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("sap-netweaver", handler)
    assert_flagged(
        findings,
        fingerprint_id="sap-netweaver",
        vendor="SAP",
        cred=Credential("Administrator", "welcome"),
    )


# ------------------------------------------------------------- sitecore cms
def test_sitecore_cms_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Sitecore Experience Platform</body></html>"
            )
        if request.url.path == "/sitecore/login":
            if (
                form_field(request, "UserName") == "admin"
                and form_field(request, "Password") == "b"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("sitecore-cms", handler)
    assert_flagged(
        findings,
        fingerprint_id="sitecore-cms",
        vendor="Sitecore",
        cred=Credential("admin", "b"),
    )


# ------------------------------------------------------------- wazuh server
def test_wazuh_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Wazuh - The Open Source Security Platform</body></html>"
            )
        if request.url.path == "/security/user/authenticate":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("wazuh-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="wazuh-server",
        vendor="Wazuh",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------------- craft cms
def test_craft_cms_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Powered by Craft CMS</body></html>"
            )
        if request.url.path == "/admin/login":
            if (
                form_field(request, "loginName") == "admin"
                and form_field(request, "password") == "password"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("craft-cms", handler)
    assert_flagged(
        findings,
        fingerprint_id="craft-cms",
        vendor="Craft CMS",
        cred=Credential("admin", "password"),
    )


# ---------------------------------------------------- gladinet centrestack
def test_gladinet_centrestack_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Gladinet CentreStack</body></html>"
            )
        if request.url.path == "/Storage/StorageLogin.aspx":
            if (
                form_field(request, "email") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("gladinet-centrestack", handler)
    assert_flagged(
        findings,
        fingerprint_id="gladinet-centrestack",
        vendor="Gladinet",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------- ivanti epm
def test_ivanti_epm_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Ivanti Endpoint Manager</body></html>"
            )
        if request.url.path == "/mvc/account/login":
            if (
                form_field(request, "UserName") == "admin"
                and form_field(request, "Password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("ivanti-epm", handler)
    assert_flagged(
        findings,
        fingerprint_id="ivanti-epm",
        vendor="Ivanti",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------- mitel sip phone
def test_mitel_sip_phone_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Mitel 6920 IP Phone</body></html>"
            )
        if request.url.path == "/cgi-bin/login.cgi":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "22222"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("mitel-sip-phone", handler)
    assert_flagged(
        findings,
        fingerprint_id="mitel-sip-phone",
        vendor="Mitel",
        cred=Credential("admin", "22222"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche16_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-16 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Fortinet FortiVoice form-auth entry: the device advertises its
    fingerprint on the landing page but the auth endpoint rejects the default
    credentials (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>FortiVoice Enterprise</body></html>"
            )
        if request.url.path == "/api/v1/AdminLogin":
            return httpx.Response(200, text="invalid")  # always reject
        return httpx.Response(404)

    findings = scan_one("fortinet-fortivoice", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "fortinet-fortivoice"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
