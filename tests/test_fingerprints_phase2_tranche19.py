"""Mock-transport tests for the nineteenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in
the nineteenth expansion (Grafana observability dashboard, Jenkins CI/CD
automation controller, Nagios XI network monitoring server, the Apache Solr
search server admin UI, the JBoss EAP / WildFly management console, Drupal
CMS administrative portal, Liferay Portal / Digital Experience Platform, and
the SugarCRM customer-relationship-management server) — internet-facing
observability, CI/CD, NMS, search-server, Java application-server, CMS,
enterprise-portal and CRM admin consoles mass-exploited across the CISA
Known Exploited Vulnerabilities (KEV) catalog. Each test drives the real
Scanner against an ``httpx.MockTransport`` emulating the target and asserts
BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for
the new entries. Mirrors the conventions in
``test_fingerprints_phase2_tranche18.py``.
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


# ----------------------------------------------------------- grafana dashboard
def test_grafana_dashboard_default_creds_flagged():
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
            return httpx.Response(200, text="Invalid username")
        return httpx.Response(404)

    findings = scan_one("grafana-dashboard", handler)
    assert_flagged(
        findings,
        fingerprint_id="grafana-dashboard",
        vendor="Grafana Labs",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------- jenkins controller
def test_jenkins_controller_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Welcome to Jenkins!</body></html>"
            )
        if request.url.path == "/j_spring_security_check":
            if (
                form_field(request, "j_username") == "admin"
                and form_field(request, "j_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid login")
        return httpx.Response(404)

    findings = scan_one("jenkins-controller", handler)
    assert_flagged(
        findings,
        fingerprint_id="jenkins-controller",
        vendor="Jenkins Project",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------------- nagios xi
def test_nagios_xi_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Nagios XI Network Monitor</body></html>"
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


# ----------------------------------------------------------------- apache solr
def test_apache_solr_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Solr Admin</body></html>"
            )
        if request.url.path == "/solr/admin/authentication":
            user, pw = basic_creds(request)
            if user == "solr" and pw == "SolrRocks":
                return httpx.Response(200, text="ok")
            return httpx.Response(401)
        return httpx.Response(404)

    findings = scan_one("apache-solr", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-solr",
        vendor="Apache",
        cred=Credential("solr", "SolrRocks"),
    )


# -------------------------------------------------------------------- jboss eap
def test_jboss_eap_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>WildFly Application Server</body></html>"
            )
        if request.url.path == "/console/login.html":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("jboss-eap", handler)
    assert_flagged(
        findings,
        fingerprint_id="jboss-eap",
        vendor="Red Hat",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------------------- drupal cms
def test_drupal_cms_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Welcome</body></html>",
                headers={"x-generator": "Drupal 10 (https://www.drupal.org)"},
            )
        if request.url.path == "/user/login":
            if (
                form_field(request, "name") == "admin"
                and form_field(request, "pass") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(
                200, text="Unrecognized username or password."
            )
        return httpx.Response(404)

    findings = scan_one("drupal-cms", handler)
    assert_flagged(
        findings,
        fingerprint_id="drupal-cms",
        vendor="Drupal Project",
        cred=Credential("admin", "admin"),
    )


# ---------------------------------------------------------------- liferay portal
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


# --------------------------------------------------------------- sugarcrm server
def test_sugarcrm_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>SugarCRM Inc.</body></html>"
            )
        if request.url.path == "/index.php":
            # query string carries module=Users&action=Authenticate
            if request.url.query.decode() == "module=Users&action=Authenticate":
                if (
                    form_field(request, "user_name") == "admin"
                    and form_field(request, "username_password") == "password"
                ):
                    return httpx.Response(200, text="ok")
                return httpx.Response(200, text="Invalid username or password")
        return httpx.Response(404)

    findings = scan_one("sugarcrm-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="sugarcrm-server",
        vendor="SugarCRM",
        cred=Credential("admin", "password"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche19_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-19 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Grafana form-auth entry: the device advertises its fingerprint on
    the landing page but the auth endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Grafana</body></html>"
            )
        if request.url.path == "/login":
            return httpx.Response(200, text="Invalid username")  # always reject
        return httpx.Response(404)

    findings = scan_one("grafana-dashboard", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "grafana-dashboard"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
