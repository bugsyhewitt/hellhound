"""Mock-transport tests for the fourteenth Phase 2 fingerprint tranche.

One test per new fingerprint entry added to the bundled ``default.yaml`` in the
fourteenth expansion (Microsoft Exchange OWA, Oracle WebLogic admin console,
Apache ActiveMQ web console, Ivanti Sentry admin portal, Sophos Web Appliance,
WatchGuard Firebox web UI, Zoho ManageEngine ADSelfService Plus, and the
Progress Flowmon monitoring console) — internet-facing management consoles,
messaging brokers, application servers and security appliances mass-exploited
across the 2020-2025 CISA KEV catalog. Each test drives the real Scanner against
an ``httpx.MockTransport`` emulating the target and asserts BOTH that:

1. the device matches the intended bundled fingerprint, and
2. the device's documented default credential pair authenticates
   (``default_creds is True``).

These run with no network and no Docker. They load the actual bundled
fingerprint set so they double as a regression check on the YAML schema for the
new entries. Mirrors the conventions in ``test_fingerprints_phase2_tranche13.py``.
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


# ------------------------------------------------------- microsoft exchange owa
def test_ms_exchange_owa_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Outlook Web App</body></html>"
            )
        if request.url.path == "/owa/auth.owa":
            if (
                form_field(request, "username") == "administrator"
                and form_field(request, "password") == "P@ssw0rd"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="incorrect")
        return httpx.Response(404)

    findings = scan_one("ms-exchange-owa", handler)
    assert_flagged(
        findings,
        fingerprint_id="ms-exchange-owa",
        vendor="Microsoft",
        cred=Credential("administrator", "P@ssw0rd"),
    )


# ---------------------------------------------------------- oracle weblogic
def test_oracle_weblogic_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>WebLogic Server Administration Console</body></html>",
            )
        if request.url.path == "/console/j_security_check":
            if (
                form_field(request, "j_username") == "weblogic"
                and form_field(request, "j_password") == "weblogic"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="Authentication Denied")
        return httpx.Response(404)

    findings = scan_one("oracle-weblogic", handler)
    assert_flagged(
        findings,
        fingerprint_id="oracle-weblogic",
        vendor="Oracle",
        cred=Credential("weblogic", "weblogic"),
    )


# ----------------------------------------------------------- apache activemq
def test_apache_activemq_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>ActiveMQ</body></html>")
        if request.url.path == "/admin/index.jsp":
            user, pw = basic_creds(request)
            if user == "admin" and pw == "admin":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    findings = scan_one("apache-activemq", handler)
    assert_flagged(
        findings,
        fingerprint_id="apache-activemq",
        vendor="Apache",
        cred=Credential("admin", "admin"),
    )


# ------------------------------------------------------------- ivanti sentry
def test_ivanti_sentry_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>MobileIron Sentry</body></html>"
            )
        if request.url.path == "/mics/login.html":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("ivanti-sentry", handler)
    assert_flagged(
        findings,
        fingerprint_id="ivanti-sentry",
        vendor="Ivanti",
        cred=Credential("admin", "admin"),
    )


# -------------------------------------------------------- sophos web appliance
def test_sophos_web_appliance_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>Sophos Web Appliance</body></html>"
            )
        if request.url.path == "/index.php":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="login failed")
        return httpx.Response(404)

    findings = scan_one("sophos-web-appliance", handler)
    assert_flagged(
        findings,
        fingerprint_id="sophos-web-appliance",
        vendor="Sophos",
        cred=Credential("admin", "admin"),
    )


# ---------------------------------------------------------- watchguard firebox
def test_watchguard_firebox_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Fireware</body></html>")
        if request.url.path == "/auth/login":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "readwrite"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("watchguard-firebox", handler)
    assert_flagged(
        findings,
        fingerprint_id="watchguard-firebox",
        vendor="WatchGuard",
        cred=Credential("admin", "readwrite"),
    )


# -------------------------------------------------- zoho adselfservice plus
def test_zoho_manageengine_adselfservice_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200, html="<html><body>ADSelfService Plus</body></html>"
            )
        if request.url.path == "/j_security_check":
            if (
                form_field(request, "j_username") == "admin"
                and form_field(request, "j_password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("zoho-manageengine-adselfservice", handler)
    assert_flagged(
        findings,
        fingerprint_id="zoho-manageengine-adselfservice",
        vendor="Zoho",
        cred=Credential("admin", "admin"),
    )


# ----------------------------------------------------------- progress flowmon
def test_progress_flowmon_default_creds_flagged():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>Flowmon</body></html>")
        if request.url.path == "/resources/oauth/token":
            if (
                form_field(request, "username") == "admin"
                and form_field(request, "password") == "admin"
            ):
                return httpx.Response(200, text="ok")
            return httpx.Response(200, text="invalid")
        return httpx.Response(404)

    findings = scan_one("progress-flowmon", handler)
    assert_flagged(
        findings,
        fingerprint_id="progress-flowmon",
        vendor="Progress",
        cred=Credential("admin", "admin"),
    )


# --------------------------------------------------- matched-but-rotated guard
def test_tranche14_entry_matched_but_creds_rotated_not_flagged():
    """A device matching a new tranche-14 fingerprint but rejecting the defaults
    is matched, not flagged — proving the auth check is real, not a free pass on
    a landing-page match.

    Uses the Oracle WebLogic form-auth entry: the device advertises its
    fingerprint on the admin console landing page but the security-check endpoint
    rejects the default credentials (returning the configured
    failure_body_contains marker)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><body>WebLogic Server Administration Console</body></html>",
            )
        if request.url.path == "/console/j_security_check":
            return httpx.Response(200, text="Authentication Denied")  # always reject
        return httpx.Response(404)

    findings = scan_one("oracle-weblogic", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "oracle-weblogic"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None


# --------------------------------------------------- basic-auth rotated guard
def test_tranche14_basic_auth_matched_but_creds_rotated_not_flagged():
    """The Apache ActiveMQ entry uses HTTP Basic auth; a device that matches but
    rejects the default Basic credentials must be matched, not flagged."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, html="<html><body>ActiveMQ</body></html>")
        if request.url.path == "/admin/index.jsp":
            return httpx.Response(401, text="unauthorized")  # always reject
        return httpx.Response(404)

    findings = scan_one("apache-activemq", handler)
    assert len(findings) == 1
    assert findings[0].fingerprint_id == "apache-activemq"
    assert findings[0].default_creds is False
    assert findings[0].matched_credential is None
