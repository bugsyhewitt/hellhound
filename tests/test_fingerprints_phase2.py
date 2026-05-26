"""Mock-transport tests for the Phase 2 fingerprint expansion.

One test per new fingerprint entry added to the bundled ``default.yaml``.
Each test drives the real Scanner against an ``httpx.MockTransport`` that
emulates the target device, and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's factory-default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for
the new entries.
"""

import asyncio
import base64

import httpx
import pytest

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
    return run(scanner.scan_host("203.0.113.42", ports=[80]))


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


# --------------------------------------------------------------------- reolink
def test_reolink_camera_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>ReoLink camera login</body></html>",
            )
        if request.url.path == "/cgi-bin/api.cgi":
            if form_field(request, "userName") == "admin" and form_field(request, "password") == "":
                return httpx.Response(200, text='{"code":0}')
            return httpx.Response(200, text='{"code":1,"error":"login failed"}')
        return httpx.Response(404)

    findings = scan_one("reolink-camera", handler)
    assert_flagged(findings, fingerprint_id="reolink-camera", vendor="Reolink", cred=Credential("admin", ""))


# ----------------------------------------------------------------- grandstream
def test_grandstream_device_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Grandstream Device Configuration</body></html>")
        if request.url.path == "/cgi-bin/dologin.cgi":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="OK")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("grandstream-device", handler)
    assert_flagged(findings, fingerprint_id="grandstream-device", vendor="Grandstream", cred=Credential("admin", "admin"))


# ------------------------------------------------------------- aruba instant on
def test_aruba_instant_on_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Aruba Instant On AP</body></html>")
        if request.url.path == "/api/v1/login":
            if basic_creds(request) == ("admin", "default123"):
                return httpx.Response(200, text='{"token":"x"}')
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("aruba-instant-on", handler)
    assert_flagged(findings, fingerprint_id="aruba-instant-on", vendor="HPE Aruba", cred=Credential("admin", "default123"))


# ----------------------------------------------------------------------- tenda
def test_tenda_router_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>Tenda Wireless Router</title></head></html>")
        if request.url.path == "/login/Auth":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="success")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("tenda-router", handler)
    assert_flagged(findings, fingerprint_id="tenda-router", vendor="Tenda", cred=Credential("admin", "admin"))


# --------------------------------------------------------------------- amcrest
def test_amcrest_nvr_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>AMCREST NVR</title></head></html>")
        if request.url.path == "/cgi-bin/magicBox.cgi":
            if basic_creds(request) == ("admin", "admin"):
                return httpx.Response(200, text="type=NVR")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("amcrest-nvr", handler)
    assert_flagged(findings, fingerprint_id="amcrest-nvr", vendor="Amcrest", cred=Credential("admin", "admin"))


# --------------------------------------------------------------------- vivotek
def test_vivotek_camera_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>VIVOTEK Network Camera</title></head></html>")
        if request.url.path == "/cgi-bin/viewer/video.jpg":
            if basic_creds(request) == ("root", ""):
                return httpx.Response(200, text="<jpegdata>")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("vivotek-camera", handler)
    assert_flagged(findings, fingerprint_id="vivotek-camera", vendor="Vivotek", cred=Credential("root", ""))


# ----------------------------------------------------------------- axis gen 2
def test_axis_camera_gen2_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>AXIS Network Camera M-series</body></html>")
        if request.url.path == "/axis-cgi/admin/param.cgi":
            if basic_creds(request) == ("root", "root"):
                return httpx.Response(200, text="root.Brand.Brand=AXIS")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("axis-camera-gen2", handler)
    assert_flagged(findings, fingerprint_id="axis-camera-gen2", vendor="Axis", cred=Credential("root", "root"))


# --------------------------------------------------------------------- linksys
def test_linksys_wrt_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            if basic_creds(request) == ("admin", "admin"):
                return httpx.Response(200, html="<html><body>WRT router</body></html>")
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": 'Basic realm="Linksys WRT"'},
                text="unauthorized",
            )
        return httpx.Response(404)

    findings = scan_one("linksys-wrt", handler)
    assert_flagged(findings, fingerprint_id="linksys-wrt", vendor="Linksys", cred=Credential("admin", "admin"))


# ------------------------------------------------------------------------ asus
def test_asus_router_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>ASUS Wireless Router RT-AC</title></head></html>")
        if request.url.path == "/login.cgi":
            if form_field(request, "login_username") == "admin" and form_field(request, "login_passwd") == "admin":
                return httpx.Response(200, text="welcome")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("asus-router", handler)
    assert_flagged(findings, fingerprint_id="asus-router", vendor="ASUS", cred=Credential("admin", "admin"))


# ------------------------------------------------------------------------ moxa
def test_moxa_nport_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>Moxa NPort 5110</title></head></html>")
        if request.url.path == "/cgi-bin/mainpage.cgi":
            if basic_creds(request) == ("admin", ""):
                return httpx.Response(200, text="overview")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("moxa-nport", handler)
    assert_flagged(findings, fingerprint_id="moxa-nport", vendor="Moxa", cred=Credential("admin", ""))


# ------------------------------------------------------------------- geovision
def test_geovision_dvr_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            if basic_creds(request) == ("admin", "admin"):
                return httpx.Response(200, html="<html><head><title>GeoVision DVR</title></head></html>")
            # Landing page is served unauthenticated for matching; auth checked again.
            return httpx.Response(200, html="<html><head><title>GeoVision DVR</title></head></html>")
        return httpx.Response(404)

    findings = scan_one("geovision-dvr", handler)
    assert_flagged(findings, fingerprint_id="geovision-dvr", vendor="GeoVision", cred=Credential("admin", "admin"))


# ----------------------------------------------------------------- netgear orbi
def test_netgear_orbi_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            if basic_creds(request) == ("admin", "password"):
                return httpx.Response(200, html="<html><head><title>Orbi</title></head></html>")
            return httpx.Response(200, html="<html><head><title>Orbi</title></head></html>")
        return httpx.Response(404)

    findings = scan_one("netgear-orbi", handler)
    assert_flagged(findings, fingerprint_id="netgear-orbi", vendor="NETGEAR", cred=Credential("admin", "password"))


# --------------------------------------------------- matched-but-rotated guard
def test_phase2_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new fingerprint but rejecting defaults is matched,
    not flagged — proving the auth check is real, not a free pass on match.

    Uses the Amcrest basic-auth entry: the device advertises its fingerprint
    on the landing page but the auth endpoint returns 401 for the default
    credentials (i.e. they have been rotated)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>AMCREST NVR</title></head></html>")
        if request.url.path == "/cgi-bin/magicBox.cgi":
            return httpx.Response(401, text="unauthorized")  # always reject
        return httpx.Response(404)

    findings = scan_one("amcrest-nvr", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "amcrest-nvr"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
