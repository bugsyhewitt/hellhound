"""Mock-transport tests for the nineteenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
nineteenth expansion (Jenkins CI/CD automation server, Grafana observability
dashboard, VMware Aria Operations for Networks (vRealize Network Insight),
Dell iDRAC out-of-band server management controller, Nagios XI monitoring
server, Rocket.Chat self-hosted team-messaging server, Portainer container /
Docker management UI, and the OpenEMR electronic-health-records portal) —
internet-facing CI/CD orchestrators, observability dashboards,
virtualisation brokers, remote-management processors, monitoring servers,
chat platforms, container UIs and EHR portals mass-exploited across the CISA
Known Exploited Vulnerabilities (KEV) catalog. Each test drives the real
Scanner against an ``httpx.MockTransport`` emulating the target and asserts
BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche18.py``.
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


# -------------------------------------------------------------------- jenkins
def test_jenkins_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Dashboard [Jenkins]</body></html>"
            )
        if request.url.path == "/j_spring_security_check":
            if (
                form_field(request, "j_username") == "admin"
                and form_field(request, "j_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid username or password")
        return httpx.Response(404)

    findings = scan_one("jenkins-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="jenkins-server",
        vendor="Jenkins",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------------------- grafana
def test_grafana_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Grafana</body></html>"
            )
        if request.url.path == "/login":
            if (
                form_field(request, "user") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid username or password")
        return httpx.Response(404)

    findings = scan_one("grafana-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="grafana-server",
        vendor="Grafana Labs",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------- vmware aria operations for networks
def test_vmware_aria_operations_networks_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>VMware Aria Operations for Networks</body></html>",
            )
        if request.url.path == "/api/auth/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid credentials")
        return httpx.Response(404)

    findings = scan_one("vmware-aria-operations-networks", handler)
    assert_flagged(
        findings,
        fingerprint_id="vmware-aria-operations-networks",
        vendor="VMware",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------------- dell idrac
def test_dell_idrac_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Integrated Dell Remote Access Controller iDRAC</body></html>",
            )
        if request.url.path == "/data/login":
            if (
                form_field(request, "user") == "root"
                and form_field(request, "password") == "calvin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Authentication failed")
        return httpx.Response(404)

    findings = scan_one("dell-idrac", handler)
    assert_flagged(
        findings,
        fingerprint_id="dell-idrac",
        vendor="Dell",
        cred=Credential("root", "calvin"),
    )


# -------------------------------------------------------------------- nagios
def test_nagios_xi_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Nagios XI</body></html>"
            )
        if request.url.path == "/nagiosxi/login.php":
            if (
                form_field(request, "username") == "nagiosadmin"
                and form_field(request, "password") == "nagiosadmin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Incorrect username/password")
        return httpx.Response(404)

    findings = scan_one("nagios-xi", handler)
    assert_flagged(
        findings,
        fingerprint_id="nagios-xi",
        vendor="Nagios Enterprises",
        cred=Credential("nagiosadmin", "nagiosadmin"),
    )


# ---------------------------------------------------------------- rocket.chat
def test_rocket_chat_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Rocket.Chat</body></html>"
            )
        if request.url.path == "/api/v1/login":
            if (
                form_field(request, "user") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Unauthorized")
        return httpx.Response(404)

    findings = scan_one("rocket-chat", handler)
    assert_flagged(
        findings,
        fingerprint_id="rocket-chat",
        vendor="Rocket.Chat",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------------ portainer
def test_portainer_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Portainer</body></html>"
            )
        if request.url.path == "/api/auth":
            if (
                form_field(request, "Username") == "admin"
                and form_field(request, "Password") == "portainer"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("portainer-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="portainer-server",
        vendor="Portainer",
        cred=Credential("admin", "portainer"),
    )


# -------------------------------------------------------------------- openemr
def test_openemr_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>OpenEMR</body></html>"
            )
        if request.url.path == "/interface/main/main_screen.php":
            if (
                form_field(request, "authUser") == "admin"
                and form_field(request, "clearPass") == "pass"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid username or password")
        return httpx.Response(404)

    findings = scan_one("openemr-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="openemr-server",
        vendor="OpenEMR Foundation",
        cred=Credential("admin", "pass"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche19_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-19 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Jenkins form-auth entry: the device advertises its fingerprint on
    the landing page but the auth endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Dashboard [Jenkins]</body></html>"
            )
        if request.url.path == "/j_spring_security_check":
            return httpx.Response(200, text="Invalid username or password")
        return httpx.Response(404)

    findings = scan_one("jenkins-server", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "jenkins-server"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
