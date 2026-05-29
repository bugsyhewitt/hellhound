"""Mock-transport tests for the fourth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
fourth expansion (Zyxel firewall, DrayTek Vigor, Ruckus AP, Edimax camera,
Four-Faith industrial router, Contec SolarView, AVTECH AVN camera, OptiLink
ONT) — network-edge and industrial classes from 2024-2025 mass-exploitation
campaigns and Mirai variant target lists. Each test drives the real Scanner
against an ``httpx.MockTransport`` emulating the target device and asserts BOTH
that:

1. the device matches the intended bundled fingerprint, and
2. the device's factory-default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche3.py``.
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
    return run(scanner.scan_host("203.0.113.88", ports=[80]))


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


# ------------------------------------------------------------- zyxel firewall
def test_zyxel_firewall_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><script src="/ext-js/login.html"></script></body></html>',
            )
        if request.url.path == "/cgi-bin/login.cgi":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "1234":
                return httpx.Response(200, text='{"result":"ok"}')
            return httpx.Response(200, text='{"result":"error"}')
        return httpx.Response(404)

    findings = scan_one("zyxel-firewall", handler)
    assert_flagged(findings, fingerprint_id="zyxel-firewall", vendor="Zyxel", cred=Credential("admin", "1234"))


# --------------------------------------------------------------- draytek vigor
def test_draytek_vigor_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>Vigor2962 Login</title></head></html>")
        if request.url.path == "/cgi-bin/wlogin.cgi":
            if form_field(request, "aa") == "admin" and form_field(request, "ab") == "admin":
                return httpx.Response(200, text="welcome")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("draytek-vigor", handler)
    assert_flagged(findings, fingerprint_id="draytek-vigor", vendor="DrayTek", cred=Credential("admin", "admin"))


# ----------------------------------------------------------------- ruckus ap
def test_ruckus_ap_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Ruckus Unleashed</body></html>")
        if request.url.path == "/admin/login.jsp":
            if form_field(request, "username") == "super" and form_field(request, "password") == "sp-admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="login failed")
        return httpx.Response(404)

    findings = scan_one("ruckus-ap", handler)
    assert_flagged(findings, fingerprint_id="ruckus-ap", vendor="Ruckus", cred=Credential("super", "sp-admin"))


# --------------------------------------------------------------- edimax camera
def test_edimax_camera_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>edimax ip camera</body></html>")
        if request.url.path == "/camera-cgi/admin/param.cgi":
            if basic_creds(request) == ("admin", "1234"):
                return httpx.Response(200, text="model=IC-3140W")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("edimax-camera", handler)
    assert_flagged(findings, fingerprint_id="edimax-camera", vendor="Edimax", cred=Credential("admin", "1234"))


# ------------------------------------------------------- four-faith router
def test_four_faith_router_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Four-Faith F3x24 Router</body></html>")
        if request.url.path == "/apply.cgi":
            if form_field(request, "username") == "apadmin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("four-faith-router", handler)
    assert_flagged(
        findings,
        fingerprint_id="four-faith-router",
        vendor="Four-Faith",
        cred=Credential("apadmin", "admin"),
    )


# ----------------------------------------------------------- contec solarview
def test_contec_solarview_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>SolarView Compact</title></head></html>")
        if request.url.path == "/login.php":
            if form_field(request, "user") == "admin" and form_field(request, "pass") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("contec-solarview", handler)
    assert_flagged(findings, fingerprint_id="contec-solarview", vendor="Contec", cred=Credential("admin", "admin"))


# ----------------------------------------------------------- avtech avn camera
def test_avtech_avn_camera_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><a href="/cgi-bin/supervisor/login">go</a></body></html>',
            )
        if request.url.path == "/cgi-bin/supervisor/Login.cgi":
            if basic_creds(request) == ("admin", "admin"):
                return httpx.Response(200, text="OK")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("avtech-avn-camera", handler)
    assert_flagged(
        findings,
        fingerprint_id="avtech-avn-camera",
        vendor="AVTECH",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------------- optilink ont
def test_optilink_ont_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>GPON Home Gateway</title></head></html>")
        if request.url.path == "/boaform/admin/formLogin":
            if form_field(request, "username") == "admin" and form_field(request, "psd") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("optilink-ont", handler)
    assert_flagged(findings, fingerprint_id="optilink-ont", vendor="OptiLink", cred=Credential("admin", "admin"))


# --------------------------------------------------- matched-but-rotated guard
def test_tranche4_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-4 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Edimax basic-auth entry: the device advertises its fingerprint on
    the landing page but the auth endpoint returns 401 for the default
    credentials (i.e. they have been rotated)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>edimax ip camera</body></html>")
        if request.url.path == "/camera-cgi/admin/param.cgi":
            return httpx.Response(401, text="unauthorized")  # always reject
        return httpx.Response(404)

    findings = scan_one("edimax-camera", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "edimax-camera"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
