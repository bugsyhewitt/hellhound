"""Mock-transport tests for the thirteenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
thirteenth expansion (Fortinet FortiOS SSL-VPN, Progress Kemp LoadMaster,
Check Point Security Gateway, Palo Alto PAN-OS management, Ivanti Virtual
Traffic Manager, NAKIVO Backup & Replication, SonicWall SMA 100, and the Zimbra
Collaboration admin console) — internet-facing VPN portals, application-delivery
controllers, firewall/management UIs, backup directors and collaboration admin
consoles mass-exploited across the 2023-2025 CISA KEV catalog. Each test drives
the real Scanner against an ``httpx.MockTransport`` emulating the target and
asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche12.py``.
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


# --------------------------------------------------------- fortinet ssl-vpn
def test_fortinet_fortios_ssl_vpn_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>sslvpn portal</body></html>"
            )
        if request.url.path == "/remote/logincheck":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "credential") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="access denied")
        return httpx.Response(404)

    findings = scan_one("fortinet-fortios-ssl-vpn", handler)
    assert_flagged(
        findings,
        fingerprint_id="fortinet-fortios-ssl-vpn",
        vendor="Fortinet",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------- progress loadmaster
def test_progress_loadmaster_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>LoadMaster</body></html>"
            )
        if request.url.path == "/progs/doconfig/login":
            if (
                form_field(request, "username") == "bal"
                and form_field(request, "password") == "1fourall"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("progress-loadmaster", handler)
    assert_flagged(
        findings,
        fingerprint_id="progress-loadmaster",
        vendor="Progress",
        cred=Credential("bal", "1fourall"),
    )


# -------------------------------------------------------- check point gateway
def test_checkpoint_gateway_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Check Point</body></html>"
            )
        if request.url.path == "/sslvpn/Login/Login":
            if (
                form_field(request, "userName") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="login failed")
        return httpx.Response(404)

    findings = scan_one("checkpoint-gateway", handler)
    assert_flagged(
        findings,
        fingerprint_id="checkpoint-gateway",
        vendor="Check Point",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------- palo alto pan-os
def test_paloalto_panos_mgmt_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>PAN-OS</body></html>")
        if request.url.path == "/php/login.php":
            if (
                form_field(request, "user") == "admin"
                and form_field(request, "passwd") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("paloalto-panos-mgmt", handler)
    assert_flagged(
        findings,
        fingerprint_id="paloalto-panos-mgmt",
        vendor="Palo Alto Networks",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------- ivanti vtm
def test_ivanti_vtm_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Virtual Traffic Manager</body></html>"
            )
        if request.url.path == "/apps/zxtm/login.cgi":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("ivanti-vtm", handler)
    assert_flagged(
        findings,
        fingerprint_id="ivanti-vtm",
        vendor="Ivanti",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------- nakivo backup
def test_nakivo_backup_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>NAKIVO</body></html>")
        if request.url.path == "/c/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="login failed")
        return httpx.Response(404)

    findings = scan_one("nakivo-backup", handler)
    assert_flagged(
        findings,
        fingerprint_id="nakivo-backup",
        vendor="NAKIVO",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------- sonicwall sma
def test_sma100_appliance_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>SMA Appliance</body></html>")
        if request.url.path == "/__api__/v1/logon":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "password"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("sma100-appliance", handler)
    assert_flagged(
        findings,
        fingerprint_id="sma100-appliance",
        vendor="SonicWall",
        cred=Credential("admin", "password"),
    )


# ----------------------------------------------------- zimbra admin console
def test_zimbra_collaboration_soap_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Zimbra Administration</body></html>"
            )
        if request.url.path == "/service/admin/soap":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="AUTH_FAILED")
        return httpx.Response(404)

    findings = scan_one("zimbra-collaboration-soap", handler)
    assert_flagged(
        findings,
        fingerprint_id="zimbra-collaboration-soap",
        vendor="Synacor",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche13_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-13 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Fortinet FortiOS SSL-VPN form-auth entry: the device advertises its
    fingerprint on the landing page but the login endpoint rejects the default
    credentials (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>sslvpn portal</body></html>"
            )
        if request.url.path == "/remote/logincheck":
            return httpx.Response(200, text="access denied")  # always reject
        return httpx.Response(404)

    findings = scan_one("fortinet-fortios-ssl-vpn", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "fortinet-fortios-ssl-vpn"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
