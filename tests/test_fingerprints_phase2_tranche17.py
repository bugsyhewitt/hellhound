"""Mock-transport tests for the seventeenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
seventeenth expansion (Cisco Smart Software Manager On-Prem licensing portal,
PTZOptics PT30X-series PTZ cameras, Trend Micro Apex One endpoint-protection
console, Synology DiskStation Manager (DSM) NAS web UI, ServiceNow Now Platform
ITSM portal, TP-Link Archer C5400X gaming-router web UI, the WSO2 Carbon
management console (API Manager / Identity Server), and Ruijie Reyee
cloud-managed access points / gateways) — internet-facing admin consoles,
SaaS-style ITSM portals, NAS dashboards, SOHO router admin UIs and IP-camera
management interfaces mass-exploited across the CISA Known Exploited
Vulnerabilities (KEV) catalog. Each test drives the real Scanner against an
``httpx.MockTransport`` emulating the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche16.py``.
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


# ------------------------------------------------------- cisco ssm on-prem
def test_cisco_ssm_on_prem_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>Cisco Smart Software Manager On-Prem</body></html>",
            )
        if request.url.path == "/backend/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "CiscoAdmin@SSM"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("cisco-ssm-on-prem", handler)
    assert_flagged(
        findings,
        fingerprint_id="cisco-ssm-on-prem",
        vendor="Cisco",
        cred=Credential("admin", "CiscoAdmin@SSM"),
    )


# ---------------------------------------------------------- ptzoptics camera
def test_ptzoptics_camera_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>PTZOptics PT30X-NDI</body></html>"
            )
        if request.url.path == "/cgi-bin/param.cgi":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("ptzoptics-camera", handler)
    assert_flagged(
        findings,
        fingerprint_id="ptzoptics-camera",
        vendor="PTZOptics",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------- trend micro apex one
def test_trend_micro_apex_one_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Trend Micro Apex One</body></html>"
            )
        if request.url.path == "/officescan/console/html/cgi/cgiChkMasterPwd.exe":
            if (
                form_field(request, "txtAccount") == "root"
                and form_field(request, "txtPasswd") == "1111"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("trend-micro-apex-one", handler)
    assert_flagged(
        findings,
        fingerprint_id="trend-micro-apex-one",
        vendor="Trend Micro",
        cred=Credential("root", "1111"),
    )


# -------------------------------------------------------------- synology dsm
def test_synology_dsm_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Synology DiskStation DS220+</body></html>"
            )
        if request.url.path == "/webman/login.cgi":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "passwd") == ""
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("synology-dsm", handler)
    assert_flagged(
        findings,
        fingerprint_id="synology-dsm",
        vendor="Synology",
        cred=Credential("admin", ""),
    )


# ------------------------------------------------------- servicenow now platform
def test_servicenow_now_platform_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>ServiceNow Now Platform</body></html>"
            )
        if request.url.path == "/login.do":
            if (
                form_field(request, "user_name") == "admin"
                and form_field(request, "user_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("servicenow-now-platform", handler)
    assert_flagged(
        findings,
        fingerprint_id="servicenow-now-platform",
        vendor="ServiceNow",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------ tp-link archer
def test_tplink_archer_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>TP-Link Archer C5400X</body></html>"
            )
        if request.url.path == "/cgi-bin/luci/;stok=/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("tplink-archer", handler)
    assert_flagged(
        findings,
        fingerprint_id="tplink-archer",
        vendor="TP-Link",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------------- wso2 carbon
def test_wso2_carbon_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>WSO2 Carbon Management Console</body></html>"
            )
        if request.url.path == "/carbon/admin/login_action.jsp":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("wso2-carbon", handler)
    assert_flagged(
        findings,
        fingerprint_id="wso2-carbon",
        vendor="WSO2",
        cred=Credential("admin", "admin"),
    )


# ---------------------------------------------------------------- ruijie reyee
def test_ruijie_reyee_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Ruijie Reyee Cloud AP</body></html>"
            )
        if request.url.path == "/api/sys/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="fail")
        return httpx.Response(404)

    findings = scan_one("ruijie-reyee", handler)
    assert_flagged(
        findings,
        fingerprint_id="ruijie-reyee",
        vendor="Ruijie",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche17_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-17 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the ServiceNow form-auth entry: the device advertises its fingerprint
    on the landing page but the auth endpoint rejects the default credentials
    (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>ServiceNow Now Platform</body></html>"
            )
        if request.url.path == "/login.do":
            return httpx.Response(200, text="invalid")  # always reject
        return httpx.Response(404)

    findings = scan_one("servicenow-now-platform", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "servicenow-now-platform"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
