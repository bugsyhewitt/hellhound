"""Mock-transport tests for the third Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
third expansion (TBK DVR, TOTOLINK, Uniview, Hanwha Wisenet, QNAP, WD My Cloud,
Hikvision ISAPI, Cisco RV). Each test drives the real Scanner against an
``httpx.MockTransport`` emulating the target device and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's factory-default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2.py``.
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
    return run(scanner.scan_host("203.0.113.77", ports=[80]))


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


# -------------------------------------------------------------------- tbk dvr
def test_tbk_dvr_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><a href="/device.rsp">device</a></body></html>',
            )
        if request.url.path == "/login.rsp":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("tbk-dvr", handler)
    assert_flagged(findings, fingerprint_id="tbk-dvr", vendor="TBK", cred=Credential("admin", "admin"))


# --------------------------------------------------------------------- totolink
def test_totolink_router_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>TOTOLINK A3002RU</title></head></html>")
        if request.url.path == "/cgi-bin/cstecgi.cgi":
            if form_field(request, "username") == "admin" and form_field(request, "password") == "admin":
                return httpx.Response(200, text='{"success":1}')
            return httpx.Response(200, text='{"success":0}')
        return httpx.Response(404)

    findings = scan_one("totolink-router", handler)
    assert_flagged(findings, fingerprint_id="totolink-router", vendor="TOTOLINK", cred=Credential("admin", "admin"))


# ---------------------------------------------------------------------- uniview
def test_uniview_nvr_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>uniview web client</body></html>")
        if request.url.path == "/LAPI/V1.0/Login":
            if form_field(request, "userName") == "admin" and form_field(request, "password") == "123456":
                return httpx.Response(200, text='{"Response":{"StatusCode":0}}')
            return httpx.Response(200, text='{"Response":{"StatusCode":1}}')
        return httpx.Response(404)

    findings = scan_one("uniview-nvr", handler)
    assert_flagged(findings, fingerprint_id="uniview-nvr", vendor="Uniview", cred=Credential("admin", "123456"))


# ---------------------------------------------------------------- hanwha wisenet
def test_hanwha_wisenet_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>WISENET Camera</title></head></html>")
        if request.url.path == "/stw-cgi/system.cgi":
            if basic_creds(request) == ("admin", "4321"):
                return httpx.Response(200, text="DeviceType=Camera")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("hanwha-wisenet", handler)
    assert_flagged(findings, fingerprint_id="hanwha-wisenet", vendor="Hanwha", cred=Credential("admin", "4321"))


# ------------------------------------------------------------------------- qnap
def test_qnap_nas_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>QNAP Turbo NAS</body></html>")
        if request.url.path == "/cgi-bin/authLogin.cgi":
            if form_field(request, "user") == "admin" and form_field(request, "pwd") == "admin":
                return httpx.Response(200, text="<authPassed>1</authPassed>")
            return httpx.Response(200, text="<authPassed>0</authPassed>")
        return httpx.Response(404)

    findings = scan_one("qnap-nas", handler)
    assert_flagged(findings, fingerprint_id="qnap-nas", vendor="QNAP", cred=Credential("admin", "admin"))


# -------------------------------------------------------------------- wd mycloud
def test_wd_mycloud_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>wdnas dashboard</body></html>")
        if request.url.path == "/cgi-bin/login_mgr.cgi":
            if form_field(request, "username") == "admin" and form_field(request, "pw") == "admin":
                return httpx.Response(200, text="<result>0</result>")
            return httpx.Response(200, text="<result>1</result>")
        return httpx.Response(404)

    findings = scan_one("wd-mycloud", handler)
    assert_flagged(findings, fingerprint_id="wd-mycloud", vendor="Western Digital", cred=Credential("admin", "admin"))


# --------------------------------------------------------- hikvision isapi (new)
def test_hikvision_isapi_camera_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html='<html><body><script src="/doc/page/login.asp"></script></body></html>',
            )
        if request.url.path == "/ISAPI/Security/userCheck":
            if basic_creds(request) == ("admin", "admin12345"):
                return httpx.Response(200, text="<statusValue>200</statusValue>")
            return httpx.Response(401)
        return httpx.Response(404)

    findings = scan_one("hikvision-isapi-camera", handler)
    assert_flagged(
        findings,
        fingerprint_id="hikvision-isapi-camera",
        vendor="Hikvision",
        cred=Credential("admin", "admin12345"),
    )


# -------------------------------------------------------------------- cisco rv
def test_cisco_rv_router_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><head><title>Cisco Small Business RV340</title></head></html>",
            )
        if request.url.path == "/login.cgi":
            if form_field(request, "username") == "cisco" and form_field(request, "password") == "cisco":
                return httpx.Response(200, text="welcome")
            return httpx.Response(200, text="error")
        return httpx.Response(404)

    findings = scan_one("cisco-rv-router", handler)
    assert_flagged(findings, fingerprint_id="cisco-rv-router", vendor="Cisco", cred=Credential("cisco", "cisco"))


# --------------------------------------------------- matched-but-rotated guard
def test_tranche3_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-3 fingerprint but rejecting the defaults is
    matched, not flagged — proving the auth check is real, not a free pass on a
    landing-page match.

    Uses the Hanwha basic-auth entry: the device advertises its fingerprint on
    the landing page but the auth endpoint returns 401 for the default
    credentials (i.e. they have been rotated)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><head><title>WISENET Camera</title></head></html>")
        if request.url.path == "/stw-cgi/system.cgi":
            return httpx.Response(401, text="unauthorized")  # always reject
        return httpx.Response(404)

    findings = scan_one("hanwha-wisenet", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "hanwha-wisenet"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
