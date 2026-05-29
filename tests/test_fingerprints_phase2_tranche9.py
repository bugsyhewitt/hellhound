"""Mock-transport tests for the ninth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
ninth expansion (Fortinet FortiManager, Sophos Firewall, D-Link DNS NAS,
Progress Kemp LoadMaster, Synacor Zimbra, Rejetto HFS, GitLab CE, NextGen Mirth
Connect) — internet-facing enterprise appliances, NAS devices, file servers and
web platforms mass-exploited across the 2024-2025 CISA KEV / ransomware
landscape. Each test drives the real Scanner against an ``httpx.MockTransport``
emulating the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche8.py``.
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


def basic_creds(request: httpx.Request) -> tuple[str, str] | None:
    """Decode an HTTP Basic Authorization header to (user, pass), or None."""
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
    except Exception:  # pragma: no cover - malformed header
        return None
    user, _, pwd = decoded.partition(":")
    return user, pwd


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


# ----------------------------------------------------------- fortinet fortimanager
def test_fortinet_fortimanager_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>FortiManager management console</body></html>")
        if request.url.path == "/p/login/":
            if form_field(request, "username") == "admin" and form_field(request, "secretkey") == "":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("fortinet-fortimanager", handler)
    assert_flagged(
        findings,
        fingerprint_id="fortinet-fortimanager",
        vendor="Fortinet",
        cred=Credential("admin", ""),
    )


# --------------------------------------------------------------- sophos firewall
def test_sophos_firewall_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Sophos Firewall WebAdmin</body></html>")
        if request.url.path == "/webconsole/Controller":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("sophos-firewall", handler)
    assert_flagged(
        findings,
        fingerprint_id="sophos-firewall",
        vendor="Sophos",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------------------- d-link dns nas
def test_dlink_dns_nas_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>ShareCenter network storage</body></html>")
        if request.url.path == "/cgi-bin/login_mgr.cgi":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("dlink-dns-nas", handler)
    assert_flagged(
        findings,
        fingerprint_id="dlink-dns-nas",
        vendor="D-Link",
        cred=Credential("admin", ""),
    )


# ------------------------------------------------------------- kemp loadmaster
def test_kemp_loadmaster_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>LoadMaster appliance management</body></html>")
        if request.url.path == "/progs/doconfig/login":
            if form_field(request, "usr") == "bal" and form_field(request, "pass") == "1fourall":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("kemp-loadmaster", handler)
    assert_flagged(
        findings,
        fingerprint_id="kemp-loadmaster",
        vendor="Progress",
        cred=Credential("bal", "1fourall"),
    )


# ------------------------------------------------------- zimbra collaboration
def test_zimbra_collaboration_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Zimbra Web Client</body></html>")
        if request.url.path == "/service/soap":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "zimbra":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("zimbra-collaboration", handler)
    assert_flagged(
        findings,
        fingerprint_id="zimbra-collaboration",
        vendor="Synacor",
        cred=Credential("admin", "zimbra"),
    )


# ------------------------------------------------------------------- rejetto hfs
def test_rejetto_hfs_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>HttpFileServer 2.3</body></html>")
        if request.url.path == "/~login":
            creds = basic_creds(request)
            if creds == ("admin", "admin"):
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("rejetto-hfs", handler)
    assert_flagged(
        findings,
        fingerprint_id="rejetto-hfs",
        vendor="Rejetto",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------------------- gitlab
def test_gitlab_ce_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>GitLab Community Edition</body></html>")
        if request.url.path == "/users/sign_in":
            if (
                form_field(request, "user[login]") == "root"
                and form_field(request, "user[password]") == "5iveL!fe"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("gitlab-ce", handler)
    assert_flagged(
        findings,
        fingerprint_id="gitlab-ce",
        vendor="GitLab",
        cred=Credential("root", "5iveL!fe"),
    )


# ----------------------------------------------------------- nextgen mirth connect
def test_nextgen_mirth_connect_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>NextGen Mirth Connect Administrator</body></html>")
        if request.url.path == "/api/users/_login":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="error")
        return httpx.Response(404)

    findings = scan_one("nextgen-mirth-connect", handler)
    assert_flagged(
        findings,
        fingerprint_id="nextgen-mirth-connect",
        vendor="NextGen Healthcare",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche9_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-9 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the GitLab form-auth entry: the device advertises its fingerprint on
    the landing page but the sign-in endpoint rejects the default credentials
    with a non-success status (i.e. they have been rotated)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>GitLab Community Edition</body></html>")
        if request.url.path == "/users/sign_in":
            return httpx.Response(401, text="error")  # always reject
        return httpx.Response(404)

    findings = scan_one("gitlab-ce", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "gitlab-ce"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
