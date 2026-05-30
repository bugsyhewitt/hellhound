"""Mock-transport tests for the twentieth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
twentieth expansion (Sonatype Nexus Repository Manager, Atlassian Jira
Server / Data Center, Apache Airflow workflow orchestration webserver, the
Nextcloud self-hosted file-sync / collaboration server, the Gitea self-hosted
Git service, vBulletin self-hosted forum software, WAGO PFC / 750-series
programmable logic controller web UI, and Schneider Electric Modicon M340 /
M580 PLC web server) — internet-facing artifact repositories, issue trackers,
workflow orchestrators, file-sync servers, source-control servers, forum
platforms and industrial PLC web UIs mass-exploited across the CISA Known
Exploited Vulnerabilities (KEV) catalog. Each test drives the real Scanner
against an ``httpx.MockTransport`` emulating the target and asserts BOTH
that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche19.py``.
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


# -------------------------------------------------------------------- nexus
def test_sonatype_nexus_repository_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Nexus Repository Manager</body></html>"
            )
        if request.url.path == "/service/rapture/session":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin123"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Incorrect username or password")
        return httpx.Response(404)

    findings = scan_one("sonatype-nexus-repository", handler)
    assert_flagged(
        findings,
        fingerprint_id="sonatype-nexus-repository",
        vendor="Sonatype",
        cred=Credential("admin", "admin123"),
    )


# --------------------------------------------------------------------- jira
def test_atlassian_jira_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>JIRA Software</body></html>"
            )
        if request.url.path == "/login.jsp":
            if (
                form_field(request, "os_username") == "admin"
                and form_field(request, "os_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Sorry, your username and password are incorrect")
        return httpx.Response(404)

    findings = scan_one("atlassian-jira", handler)
    assert_flagged(
        findings,
        fingerprint_id="atlassian-jira",
        vendor="Atlassian",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------------ airflow
def test_apache_airflow_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Sign In - Airflow</body></html>"
            )
        if request.url.path == "/login/":
            if (
                form_field(request, "username") == "airflow"
                and form_field(request, "password") == "airflow"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid login. Please try again.")
        return httpx.Response(404)

    findings = scan_one("apache-airflow", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-airflow",
        vendor="Apache Software Foundation",
        cred=Credential("airflow", "airflow"),
    )


# ---------------------------------------------------------------- nextcloud
def test_nextcloud_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Nextcloud</body></html>"
            )
        if request.url.path == "/login":
            if (
                form_field(request, "user") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Wrong username or password.")
        return httpx.Response(404)

    findings = scan_one("nextcloud-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="nextcloud-server",
        vendor="Nextcloud",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------------------- gitea
def test_gitea_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Gitea: Git with a cup of tea</body></html>"
            )
        if request.url.path == "/user/login":
            if (
                form_field(request, "user_name") == "gitea"
                and form_field(request, "password") == "gitea"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(
                200, text="Username or password is incorrect."
            )
        return httpx.Response(404)

    findings = scan_one("gitea-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="gitea-server",
        vendor="Gitea",
        cred=Credential("gitea", "gitea"),
    )


# ---------------------------------------------------------------- vbulletin
def test_vbulletin_forum_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Powered by vBulletin</body></html>"
            )
        if request.url.path == "/admincp/login.php":
            if (
                form_field(request, "vb_login_username") == "admin"
                and form_field(request, "vb_login_password") == "password"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Your username or password was incorrect")
        return httpx.Response(404)

    findings = scan_one("vbulletin-forum", handler)
    assert_flagged(
        findings,
        fingerprint_id="vbulletin-forum",
        vendor="vBulletin",
        cred=Credential("admin", "password"),
    )


# --------------------------------------------------------------------- wago
def test_wago_plc_controller_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>WAGO 750-8212 PFC200</body></html>"
            )
        if request.url.path == "/wbm":
            user, pw = basic_creds(request)
            if user == "admin" and pw == "wago":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="Unauthorized")
        return httpx.Response(404)

    findings = scan_one("wago-plc-controller", handler)
    assert_flagged(
        findings,
        fingerprint_id="wago-plc-controller",
        vendor="WAGO",
        cred=Credential("admin", "wago"),
    )


# ---------------------------------------------------------------- schneider
def test_schneider_modicon_plc_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Schneider Electric Modicon M340</body></html>",
            )
        if request.url.path == "/secure/system/login_handler.htm":
            if (
                form_field(request, "username") == "USER"
                and form_field(request, "password") == "USER"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Authentication failed")
        return httpx.Response(404)

    findings = scan_one("schneider-modicon-plc", handler)
    assert_flagged(
        findings,
        fingerprint_id="schneider-modicon-plc",
        vendor="Schneider Electric",
        cred=Credential("USER", "USER"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche20_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-20 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Jira form-auth entry: the device advertises its fingerprint on the
    landing page but the auth endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>JIRA Software</body></html>"
            )
        if request.url.path == "/login.jsp":
            return httpx.Response(
                200, text="Sorry, your username and password are incorrect"
            )
        return httpx.Response(404)

    findings = scan_one("atlassian-jira", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "atlassian-jira"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
