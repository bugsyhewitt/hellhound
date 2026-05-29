"""Mock-transport tests for the eighth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
eighth expansion (Progress WhatsUp Gold, Apache Struts 2, Palo Alto PAN-OS
GlobalProtect, Ivanti Avalanche, VMware vCenter, CrushFTP, CyberPanel, Array
Networks AG) — internet-facing enterprise edge appliances and web applications
mass-exploited across the 2024-2025 CISA KEV / ransomware landscape. Each test
drives the real Scanner against an ``httpx.MockTransport`` emulating the target
and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche7.py``.
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


# --------------------------------------------------------------- whatsup gold
def test_whatsup_gold_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>WhatsUp Gold network monitor</body></html>")
        if request.url.path == "/NmConsole/api/core/authenticate":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("whatsup-gold", handler)
    assert_flagged(
        findings,
        fingerprint_id="whatsup-gold",
        vendor="Progress",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------------- apache struts2
def test_apache_struts2_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Powered by Struts2 framework</body></html>")
        if request.url.path == "/login.action":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("apache-struts2", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-struts2",
        vendor="Apache",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------- paloalto globalprotect
def test_paloalto_globalprotect_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>GlobalProtect Portal</body></html>")
        if request.url.path == "/php/login.php":
            if form_field(request, "user") == "admin" and form_field(request, "passwd") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("paloalto-globalprotect", handler)
    assert_flagged(
        findings,
        fingerprint_id="paloalto-globalprotect",
        vendor="Palo Alto Networks",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------------- ivanti avalanche
def test_ivanti_avalanche_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Ivanti Avalanche Console</body></html>")
        if request.url.path == "/AvalancheWeb/login":
            if form_field(request, "username") == "amcadmin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("ivanti-avalanche", handler)
    assert_flagged(
        findings,
        fingerprint_id="ivanti-avalanche",
        vendor="Ivanti",
        cred=Credential("amcadmin", "admin"),
    )


# --------------------------------------------------------------- vmware vcenter
def test_vmware_vcenter_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>vSphere Client login</body></html>")
        if request.url.path == "/ui/login":
            user = form_field(request, "username")
            pwd = form_field(request, "password")
            if user == "administrator@vsphere.local" and pwd == "VMware1!":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("vmware-vcenter", handler)
    assert_flagged(
        findings,
        fingerprint_id="vmware-vcenter",
        vendor="VMware",
        cred=Credential("administrator@vsphere.local", "VMware1!"),
    )


# ------------------------------------------------------------------- crushftp
def test_crushftp_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>CrushFTP Web Interface</body></html>")
        if request.url.path == "/WebInterface/function/":
            if form_field(request, "user") == "crushadmin" and form_field(request, "pass") == "crushadmin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("crushftp", handler)
    assert_flagged(
        findings,
        fingerprint_id="crushftp",
        vendor="CrushFTP",
        cred=Credential("crushadmin", "crushadmin"),
    )


# ------------------------------------------------------------------- cyberpanel
def test_cyberpanel_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>CyberPanel hosting control panel</body></html>")
        if request.url.path == "/login/authLogin":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "1234567":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("cyberpanel", handler)
    assert_flagged(
        findings,
        fingerprint_id="cyberpanel",
        vendor="CyberPanel",
        cred=Credential("admin", "1234567"),
    )


# ----------------------------------------------------------- array networks ag
def test_array_networks_ag_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Array Networks SSL VPN</body></html>")
        if request.url.path == "/prx/000/http/localhost/login":
            if form_field(request, "username") == "array" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("array-networks-ag", handler)
    assert_flagged(
        findings,
        fingerprint_id="array-networks-ag",
        vendor="Array Networks",
        cred=Credential("array", "admin"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche8_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-8 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the CrushFTP form-auth entry: the device advertises its fingerprint on
    the landing page but the login endpoint rejects the default credentials with
    a non-success status (i.e. they have been rotated)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>CrushFTP Web Interface</body></html>")
        if request.url.path == "/WebInterface/function/":
            return httpx.Response(401, text="error")  # always reject
        return httpx.Response(404)

    findings = scan_one("crushftp", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "crushftp"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
