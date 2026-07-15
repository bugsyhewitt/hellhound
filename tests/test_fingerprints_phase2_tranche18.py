"""Mock-transport tests for the eighteenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
eighteenth expansion (JetBrains TeamCity CI/CD server, Fortra GoAnywhere MFT,
Splunk Enterprise SIEM, Apache Superset data-exploration platform, Atlassian
Bitbucket Server / Data Center, Lexmark network printers / MFP embedded web
server, the GLPI IT asset / service-management portal, and Apache HugeGraph
graph-database server) — internet-facing CI/CD, MFT, SIEM, BI, source-control,
network-printer, ITSM and graph-database admin consoles mass-exploited across
the CISA Known Exploited Vulnerabilities (KEV) catalog. Each test drives the
real Scanner against an ``httpx.MockTransport`` emulating the target and
asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche17.py``.
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


# ----------------------------------------------------------- jetbrains teamcity
def test_jetbrains_teamcity_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>JetBrains TeamCity 2024.03</body></html>"
            )
        if request.url.path == "/login.html":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("jetbrains-teamcity", handler)
    assert_flagged(
        findings,
        fingerprint_id="jetbrains-teamcity",
        vendor="JetBrains",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------- fortra goanywhere mft
def test_fortra_goanywhere_mft_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Fortra GoAnywhere MFT Administrator</body></html>",
            )
        if request.url.path == "/goanywhere/auth/Login.xhtml":
            if (
                form_field(request, "j_username") == "administrator"
                and form_field(request, "j_password") == "goanywhere"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("fortra-goanywhere-mft", handler)
    assert_flagged(
        findings,
        fingerprint_id="fortra-goanywhere-mft",
        vendor="Fortra",
        cred=Credential("administrator", "goanywhere"),
    )


# ------------------------------------------------------------ splunk enterprise
def test_splunk_enterprise_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>splunk Web</body></html>"
            )
        if request.url.path == "/en-US/account/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "changeme"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("splunk-enterprise", handler)
    assert_flagged(
        findings,
        fingerprint_id="splunk-enterprise",
        vendor="Splunk",
        cred=Credential("admin", "changeme"),
    )


# -------------------------------------------------------------- apache superset
def test_apache_superset_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Apache Superset</body></html>"
            )
        if request.url.path == "/login/":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("apache-superset", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-superset",
        vendor="Apache",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------- atlassian bitbucket
def test_atlassian_bitbucket_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Atlassian Bitbucket Server</body></html>",
            )
        if request.url.path == "/j_atl_security_check":
            if (
                form_field(request, "j_username") == "admin"
                and form_field(request, "j_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("atlassian-bitbucket", handler)
    assert_flagged(
        findings,
        fingerprint_id="atlassian-bitbucket",
        vendor="Atlassian",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------------- lexmark printer
def test_lexmark_printer_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Lexmark MX711 Embedded Web Server</body></html>",
            )
        if request.url.path == "/cgi-bin/dynamic/webapps/login/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == ""
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("lexmark-printer", handler)
    assert_flagged(
        findings,
        fingerprint_id="lexmark-printer",
        vendor="Lexmark",
        cred=Credential("admin", ""),
    )


# ------------------------------------------------------------------ glpi server
def test_glpi_server_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>GLPI Asset Manager</body></html>"
            )
        if request.url.path == "/front/login.php":
            if (
                form_field(request, "login_name") == "glpi"
                and form_field(request, "login_password") == "glpi"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("glpi-server", handler)
    assert_flagged(
        findings,
        fingerprint_id="glpi-server",
        vendor="GLPI Project",
        cred=Credential("glpi", "glpi"),
    )


# ------------------------------------------------------------- apache hugegraph
def test_apache_hugegraph_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Apache HugeGraph Hubble</body></html>",
            )
        if request.url.path == "/apis/login":
            if (
                form_field(request, "name") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("apache-hugegraph", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-hugegraph",
        vendor="Apache",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche18_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-18 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the JetBrains TeamCity form-auth entry: the device advertises its
    fingerprint on the landing page but the auth endpoint rejects the default
    credentials (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>JetBrains TeamCity 2024.03</body></html>"
            )
        if request.url.path == "/login.html":
            return httpx.Response(200, text="incorrect")  # always reject
        return httpx.Response(404)

    findings = scan_one("jetbrains-teamcity", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "jetbrains-teamcity"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
