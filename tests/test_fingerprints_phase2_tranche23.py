"""Mock-transport tests for the twenty-third Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
twenty-third expansion (Zabbix network monitoring server, Apache Superset BI
application, SonarQube continuous code-quality server, Portainer CE container
management UI, Netdata real-time monitoring agent, pgAdmin 4 PostgreSQL web UI,
Rundeck job automation server, and Gitblit Java Git repository server) — additional
internet-facing DevOps, monitoring, database-administration, and self-hosted
cloud-storage servers mass-exploited across the CISA Known Exploited
Vulnerabilities (KEV) catalog. Each test drives the real Scanner against an
``httpx.MockTransport`` emulating the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche22.py``.
"""

import httpx

from hellhound.fingerprint import Credential
from _fingerprint_helpers import (
    BUNDLED,
    assert_flagged,
    basic_creds,
    form_field,
    fp,
    scan_one,
)


# ------------------------------------------------------------- zabbix
def test_zabbix_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Zabbix</body></html>"
            )
        if request.url.path == "/index.php":
            if (
                form_field(request, "name") == "Admin"
                and form_field(request, "password") == "zabbix"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Login name or password is incorrect")
        return httpx.Response(404)

    findings = scan_one("zabbix-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="zabbix-server",
        vendor="Zabbix SIA",
        cred=Credential("Admin", "zabbix"),
    )


# ---------------------------------------------------------- superset
def test_apache_superset_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Apache Superset</body></html>"
            )
        if request.url.path == "/api/v1/security/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "general"
            ):
                return httpx.Response(200, text='{"access_token":"tok"}')
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("apache-superset-ui", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-superset-ui",
        vendor="Apache Software Foundation",
        cred=Credential("admin", "general"),
    )


# --------------------------------------------------------- sonarqube
def test_sonarqube_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>SonarQube</body></html>"
            )
        if request.url.path == "/api/authentication/login":
            if (
                form_field(request, "login") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="Unauthorized")
        return httpx.Response(404)

    findings = scan_one("sonarqube-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="sonarqube-server",
        vendor="SonarSource",
        cred=Credential("admin", "admin"),
    )


# ---------------------------------------------------------- portainer
def test_portainer_ce_default_creds_flagged():
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
                return httpx.Response(200, text='{"jwt":"tok"}')
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("portainer-ce", handler)
    assert_flagged(
        findings,
        fingerprint_id="portainer-ce",
        vendor="Portainer.io",
        cred=Credential("admin", "portainer"),
    )


# ----------------------------------------------------------- netdata
def test_netdata_agent_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>netdata</body></html>"
            )
        if request.url.path == "/api/v1/info":
            user, pw = basic_creds(request)
            if user == "admin" and pw == "admin":
                return httpx.Response(200, text='{"version":"1.0"}')
            return httpx.Response(401, text="Unauthorized")
        return httpx.Response(404)

    findings = scan_one("netdata-agent", handler)
    assert_flagged(
        findings,
        fingerprint_id="netdata-agent",
        vendor="Netdata Inc.",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------ pgadmin
def test_pgadmin_web_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>pgAdmin</body></html>"
            )
        if request.url.path == "/login":
            if (
                form_field(request, "email") == "pgadmin4@pgadmin.org"
                and form_field(request, "password") == "pgadmin4"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Incorrect username or password")
        return httpx.Response(404)

    findings = scan_one("pgadmin-web", handler)
    assert_flagged(
        findings,
        fingerprint_id="pgadmin-web",
        vendor="The PostgreSQL Global Development Group",
        cred=Credential("pgadmin4@pgadmin.org", "pgadmin4"),
    )


# ----------------------------------------------------------- rundeck
def test_rundeck_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Rundeck</body></html>"
            )
        if request.url.path == "/j_security_check":
            if (
                form_field(request, "j_username") == "admin"
                and form_field(request, "j_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid Username or Password")
        return httpx.Response(404)

    findings = scan_one("rundeck-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="rundeck-server",
        vendor="PagerDuty",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------- gitblit
def test_gitblit_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Gitblit</body></html>"
            )
        if request.url.path == "/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Invalid credentials")
        return httpx.Response(404)

    findings = scan_one("gitblit-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="gitblit-server",
        vendor="Gitblit",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------- matched-but-rotated guard
def test_tranche23_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-23 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real.

    Uses the Zabbix form-auth entry: the device advertises its fingerprint on
    the landing page but the auth endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Zabbix</body></html>"
            )
        if request.url.path == "/index.php":
            return httpx.Response(200, text="Login name or password is incorrect")
        return httpx.Response(404)

    findings = scan_one("zabbix-server", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "zabbix-server"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
