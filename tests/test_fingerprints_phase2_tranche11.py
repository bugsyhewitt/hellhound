"""Mock-transport tests for the eleventh Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
eleventh expansion (Cleo Harmony, TerraMaster NAS, VMware ESXi host client,
Palo Alto Expedition, Magento / Adobe Commerce, Aviatrix Controller, F5 BIG-IP
TMUI, Kibana) — internet-facing managed-file-transfer servers, NAS appliances,
hypervisor and cloud-networking consoles, e-commerce admin panels and ADC
management UIs mass-exploited across the 2024-2025 CISA KEV / ransomware
landscape. Each test drives the real Scanner against an ``httpx.MockTransport``
emulating the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche10.py``.
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


# ----------------------------------------------------------------- cleo harmony
def test_cleo_harmony_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Cleo Harmony console</body></html>")
        if request.url.path == "/Synchronization/login":
            if (
                form_field(request, "username") == "administrator"
                and form_field(request, "password") == "Admin1234"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="login error")
        return httpx.Response(404)

    findings = scan_one("cleo-harmony", handler)
    assert_flagged(
        findings,
        fingerprint_id="cleo-harmony",
        vendor="Cleo",
        cred=Credential("administrator", "Admin1234"),
    )


# ------------------------------------------------------------- terramaster nas
def test_terramaster_nas_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>TerraMaster TOS</body></html>")
        if request.url.path == "/tos/index.php":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("terramaster-nas", handler)
    assert_flagged(
        findings,
        fingerprint_id="terramaster-nas",
        vendor="TerraMaster",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------ vmware esxi host client
def test_vmware_esxi_hostclient_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>VMware ESXi Host Client</body></html>")
        if request.url.path == "/ui/login":
            if (
                form_field(request, "username") == "root"
                and form_field(request, "password") == "vmware"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("vmware-esxi-hostclient", handler)
    assert_flagged(
        findings,
        fingerprint_id="vmware-esxi-hostclient",
        vendor="VMware",
        cred=Credential("root", "vmware"),
    )


# ------------------------------------------------------- palo alto expedition
def test_paloalto_expedition_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Palo Alto Expedition</body></html>")
        if request.url.path == "/OS/startup/login.php":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "paloalto"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("paloalto-expedition", handler)
    assert_flagged(
        findings,
        fingerprint_id="paloalto-expedition",
        vendor="Palo Alto",
        cred=Credential("admin", "paloalto"),
    )


# ------------------------------------------------------------------ magento admin
def test_magento_admin_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Magento Admin</body></html>")
        if request.url.path == "/admin/admin/index/index/":
            if (
                form_field(request, "login[username]") == "admin"
                and form_field(request, "login[password]") == "admin123"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("magento-admin", handler)
    assert_flagged(
        findings,
        fingerprint_id="magento-admin",
        vendor="Adobe",
        cred=Credential("admin", "admin123"),
    )


# ------------------------------------------------------- aviatrix controller
def test_aviatrix_controller_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Aviatrix Controller</body></html>")
        if request.url.path == "/v1/api":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "Aviatrix123#"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("aviatrix-controller", handler)
    assert_flagged(
        findings,
        fingerprint_id="aviatrix-controller",
        vendor="Aviatrix",
        cred=Credential("admin", "Aviatrix123#"),
    )


# ------------------------------------------------------------- f5 big-ip tmui
def test_f5_bigip_tmui_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>BIG-IP Configuration Utility</body></html>")
        if request.url.path == "/tmui/logmein.html":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "passwd") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="access denied")
        return httpx.Response(404)

    findings = scan_one("f5-bigip-tmui", handler)
    assert_flagged(
        findings,
        fingerprint_id="f5-bigip-tmui",
        vendor="F5",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------- kibana dashboard
def test_kibana_dashboard_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Welcome to Kibana</body></html>")
        if request.url.path == "/internal/security/login":
            if (
                form_field(request, "username") == "elastic"
                and form_field(request, "password") == "changeme"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("kibana-dashboard", handler)
    assert_flagged(
        findings,
        fingerprint_id="kibana-dashboard",
        vendor="Elastic",
        cred=Credential("elastic", "changeme"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche11_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-11 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Cleo Harmony form-auth entry: the device advertises its fingerprint
    on the landing page but the login endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Cleo Harmony console</body></html>")
        if request.url.path == "/Synchronization/login":
            return httpx.Response(200, text="login error")  # always reject
        return httpx.Response(404)

    findings = scan_one("cleo-harmony", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "cleo-harmony"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
