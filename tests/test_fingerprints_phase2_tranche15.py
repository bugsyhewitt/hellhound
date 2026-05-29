"""Mock-transport tests for the fifteenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
fifteenth expansion (SonicWall SonicOS SSL-VPN, Fortinet FortiWLM, Dasan GPON
home router, VMware Workspace ONE Access, Nortek Linear eMerge access control,
Microsoft SharePoint Server, D-Link DIR-series router, and the DNN Platform /
DotNetNuke CMS) — internet-facing firewalls, wireless managers, SOHO routers,
identity portals, access-control panels and CMS admin consoles mass-exploited
across the CISA Known Exploited Vulnerabilities (KEV) catalog. Each test drives
the real Scanner against an ``httpx.MockTransport`` emulating the target and
asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche14.py``.
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


# --------------------------------------------------------- sonicwall sonicos
def test_sonicwall_sonicos_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>SonicWall Network Security Appliance</body></html>"
            )
        if request.url.path == "/api/sonicos/auth":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "password"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("sonicwall-sonicos", handler)
    assert_flagged(
        findings,
        fingerprint_id="sonicwall-sonicos",
        vendor="SonicWall",
        cred=Credential("admin", "password"),
    )


# ---------------------------------------------------------- fortinet fortiwlm
def test_fortinet_fortiwlm_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>FortiWLM Wireless Manager</body></html>"
            )
        if request.url.path == "/ems/cli/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("fortinet-fortiwlm", handler)
    assert_flagged(
        findings,
        fingerprint_id="fortinet-fortiwlm",
        vendor="Fortinet",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------- dasan gpon router
def test_dasan_gpon_router_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>GPON Home Gateway</body></html>"
            )
        if request.url.path == "/login.cgi":
            if (
                form_field(request, "XWebPageName") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("dasan-gpon-router", handler)
    assert_flagged(
        findings,
        fingerprint_id="dasan-gpon-router",
        vendor="Dasan",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------- vmware workspace one access
def test_vmware_workspace_one_access_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>VMware Workspace ONE Access</body></html>"
            )
        if request.url.path == "/SAAS/API/1.0/REST/auth/system/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("vmware-workspace-one-access", handler)
    assert_flagged(
        findings,
        fingerprint_id="vmware-workspace-one-access",
        vendor="VMware",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------- nortek linear emerge
def test_nortek_linear_emerge_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Linear eMerge E3-Series</body></html>"
            )
        if request.url.path == "/card_scan.php":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("nortek-linear-emerge", handler)
    assert_flagged(
        findings,
        fingerprint_id="nortek-linear-emerge",
        vendor="Nortek",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------- microsoft sharepoint
def test_microsoft_sharepoint_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Microsoft SharePoint</body></html>"
            )
        if request.url.path == "/_layouts/15/Authenticate.aspx":
            if (
                form_field(request, "username") == "administrator"
                and form_field(request, "password") == "P@ssw0rd"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("microsoft-sharepoint", handler)
    assert_flagged(
        findings,
        fingerprint_id="microsoft-sharepoint",
        vendor="Microsoft",
        cred=Credential("administrator", "P@ssw0rd"),
    )


# ------------------------------------------------------------- dlink dir router
def test_dlink_dir_router_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>D-Link DIR-859 Wireless Router</body></html>"
            )
        if request.url.path == "/HNAP1/":
            if (
                form_field(request, "Login") == "admin"
                and form_field(request, "Password") == ""
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("dlink-dir-router", handler)
    assert_flagged(
        findings,
        fingerprint_id="dlink-dir-router",
        vendor="D-Link",
        cred=Credential("admin", ""),
    )


# --------------------------------------------------------- dotnetnuke / dnn
def test_dotnetnuke_dnn_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>DotNetNuke Platform</body></html>"
            )
        if request.url.path == "/Login":
            if (
                form_field(request, "txtUsername") == "host"
                and form_field(request, "txtPassword") == "dnnhost"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("dotnetnuke-dnn", handler)
    assert_flagged(
        findings,
        fingerprint_id="dotnetnuke-dnn",
        vendor="DNN",
        cred=Credential("host", "dnnhost"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche15_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-15 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the SonicWall SonicOS form-auth entry: the device advertises its
    fingerprint on the landing page but the auth endpoint rejects the default
    credentials (returning the configured failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>SonicWall Network Security Appliance</body></html>"
            )
        if request.url.path == "/api/sonicos/auth":
            return httpx.Response(200, text="invalid")  # always reject
        return httpx.Response(404)

    findings = scan_one("sonicwall-sonicos", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "sonicwall-sonicos"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
