"""Mock-transport tests for the twelfth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
twelfth expansion (Ivanti Cloud Services Appliance, Versa Director, Trimble
Cityworks, SimpleHelp, Mitel MiCollab, BeyondTrust Privileged Remote Access,
Cisco ASA/FTD WebVPN, Juniper Junos J-Web) — internet-facing edge gateways,
SD-WAN and remote-support consoles, government asset-management portals, UC
collaboration servers, VPN and firewall management UIs mass-exploited across
the 2023-2025 CISA KEV catalog. Each test drives the real Scanner against an
``httpx.MockTransport`` emulating the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche11.py``.
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


# --------------------------------------------------------------- ivanti csa
def test_ivanti_csa_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Ivanti Cloud Services Appliance</body></html>"
            )
        if request.url.path == "/client/index.php":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("ivanti-csa", handler)
    assert_flagged(
        findings,
        fingerprint_id="ivanti-csa",
        vendor="Ivanti",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------- versa director
def test_versa_director_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Versa Director</body></html>")
        if request.url.path == "/versa/login":
            if (
                form_field(request, "username") == "Administrator"
                and form_field(request, "password") == "versa123"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("versa-director", handler)
    assert_flagged(
        findings,
        fingerprint_id="versa-director",
        vendor="Versa Networks",
        cred=Credential("Administrator", "versa123"),
    )


# ----------------------------------------------------------- trimble cityworks
def test_trimble_cityworks_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Cityworks</body></html>")
        if request.url.path == "/Login/Authenticate":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("trimble-cityworks", handler)
    assert_flagged(
        findings,
        fingerprint_id="trimble-cityworks",
        vendor="Trimble",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------------- simplehelp
def test_simplehelp_remote_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>SimpleHelp</body></html>")
        if request.url.path == "/authenticate":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("simplehelp-remote", handler)
    assert_flagged(
        findings,
        fingerprint_id="simplehelp-remote",
        vendor="SimpleHelp",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------ mitel micollab
def test_mitel_micollab_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>MiCollab</body></html>")
        if request.url.path == "/awc/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="login failed")
        return httpx.Response(404)

    findings = scan_one("mitel-micollab", handler)
    assert_flagged(
        findings,
        fingerprint_id="mitel-micollab",
        vendor="Mitel",
        cred=Credential("admin", "admin"),
    )


# ---------------------------------------------------------- beyondtrust pra
def test_beyondtrust_pra_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>BeyondTrust</body></html>")
        if request.url.path == "/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="access denied")
        return httpx.Response(404)

    findings = scan_one("beyondtrust-pra", handler)
    assert_flagged(
        findings,
        fingerprint_id="beyondtrust-pra",
        vendor="BeyondTrust",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------- cisco asa webvpn
def test_cisco_asa_webvpn_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>WebVPN Service</body></html>")
        if request.url.path == "/+webvpn+/index.html":
            if (
                form_field(request, "username") == "cisco"
                and form_field(request, "password") == "cisco"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("cisco-asa-webvpn", handler)
    assert_flagged(
        findings,
        fingerprint_id="cisco-asa-webvpn",
        vendor="Cisco",
        cred=Credential("cisco", "cisco"),
    )


# ----------------------------------------------------------- juniper j-web
def test_juniper_jweb_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>J-Web</body></html>")
        if request.url.path == "/webauth_operation.php":
            if (
                form_field(request, "username") == "root"
                and form_field(request, "password") == "juniper123"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("juniper-jweb", handler)
    assert_flagged(
        findings,
        fingerprint_id="juniper-jweb",
        vendor="Juniper Networks",
        cred=Credential("root", "juniper123"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche12_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-12 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Ivanti CSA form-auth entry: the device advertises its fingerprint on
    the landing page but the login endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Ivanti Cloud Services Appliance</body></html>"
            )
        if request.url.path == "/client/index.php":
            return httpx.Response(200, text="error")  # always reject
        return httpx.Response(404)

    findings = scan_one("ivanti-csa", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "ivanti-csa"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
