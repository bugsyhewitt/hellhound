"""Tests for per-host retry with exponential backoff (POST_V01 Rank 6).

A flaky IoT webserver often drops the first connection. With ``retries`` set
above 1, hellhound retries transient transport errors and recovers the finding
that a single attempt would have missed. These tests use httpx.MockTransport so
they run with no network and no Docker, and set ``backoff=0`` so retry timing
doesn't slow the suite.
"""

import asyncio

import httpx

from hellhound.fingerprint import AuthCheck, Credential, Fingerprint, MatchCriteria
from hellhound.scanner import Scanner


def run(coro):
    return asyncio.run(coro)


def hikvision_fingerprint() -> Fingerprint:
    return Fingerprint(
        id="hikvision-dvr",
        vendor="Hikvision",
        model_class="DVR / NVR / IP Camera",
        severity="critical",
        match=MatchCriteria(path="/", http_title="Hikvision"),
        credentials=[Credential("admin", "12345")],
        auth=AuthCheck(type="basic", path="/ISAPI/Security/userCheck"),
    )


def make_flaky_handler(*, fail_first_n: int):
    """Return a MockTransport handler that raises ConnectError on the first
    *fail_first_n* requests to ``/`` then serves a Hikvision landing page.

    The auth endpoint always accepts admin/12345 so a successful landing-page
    fetch leads to a flagged finding.
    """
    state = {"landing_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            state["landing_calls"] += 1
            if state["landing_calls"] <= fail_first_n:
                raise httpx.ConnectError("connection refused")
            return httpx.Response(
                200,
                html="<html><head><title>Hikvision Network Camera</title></head></html>",
            )
        if request.url.path == "/ISAPI/Security/userCheck":
            auth = request.headers.get("authorization", "")
            if auth == "Basic YWRtaW46MTIzNDU=":
                return httpx.Response(200, text="ok")
            return httpx.Response(401, text="unauthorized")
        return httpx.Response(404)

    return handler, state


def test_retry_recovers_after_one_transient_failure():
    """Connection fails once, then succeeds — with retries=2 the finding is still produced."""
    handler, state = make_flaky_handler(fail_first_n=1)
    transport = httpx.MockTransport(handler)
    scanner = Scanner(
        fingerprints=[hikvision_fingerprint()],
        transport=transport,
        retries=2,
        backoff=0,  # keep the test instant
    )

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))

    assert len(findings) == 1
    assert findings[0].default_creds is True
    # the landing page was requested twice: one failure, one success
    assert state["landing_calls"] == 2


def test_default_no_retry_misses_flaky_host():
    """With the default retries=1, a single transient failure yields no finding."""
    handler, state = make_flaky_handler(fail_first_n=1)
    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))

    assert findings == []
    # only one attempt was made — no retry
    assert state["landing_calls"] == 1


def test_retries_exhausted_yields_no_finding():
    """If every attempt fails, the host is silently dropped (no crash)."""
    handler, state = make_flaky_handler(fail_first_n=10)
    transport = httpx.MockTransport(handler)
    scanner = Scanner(
        fingerprints=[hikvision_fingerprint()],
        transport=transport,
        retries=3,
        backoff=0,
    )

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))

    assert findings == []
    # exactly `retries` attempts were made before giving up
    assert state["landing_calls"] == 3


def test_retries_below_one_is_clamped():
    """A retries value below 1 is clamped to a single attempt."""
    scanner = Scanner(fingerprints=[], retries=0)
    assert scanner._retries == 1
    scanner = Scanner(fingerprints=[], retries=-5)
    assert scanner._retries == 1


def test_auth_endpoint_retries():
    """A transient failure on the auth check is retried too, not just the landing page."""
    state = {"auth_calls": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><head><title>Hikvision</title></head></html>",
            )
        if request.url.path == "/ISAPI/Security/userCheck":
            state["auth_calls"] += 1
            if state["auth_calls"] == 1:
                raise httpx.ConnectError("reset")
            return httpx.Response(200, text="ok")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    scanner = Scanner(
        fingerprints=[hikvision_fingerprint()],
        transport=transport,
        retries=2,
        backoff=0,
    )

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))

    assert len(findings) == 1
    assert findings[0].default_creds is True
    assert state["auth_calls"] == 2


def test_backoff_delay_grows_with_attempt(monkeypatch):
    """Backoff sleeps before each retry: backoff * (attempt - 1)."""
    handler, _ = make_flaky_handler(fail_first_n=2)
    transport = httpx.MockTransport(handler)
    scanner = Scanner(
        fingerprints=[hikvision_fingerprint()],
        transport=transport,
        retries=3,
        backoff=0.5,
    )

    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr("hellhound.scanner.asyncio.sleep", fake_sleep)

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))

    assert len(findings) == 1
    # two retries needed (attempts 2 and 3) -> backoff before each
    assert sleeps == [0.5, 1.0]


def test_cli_retries_flag_parsed():
    from hellhound.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["--target", "192.0.2.1", "--retries", "3"])
    assert args.retries == 3
    # default is a single attempt
    args = parser.parse_args(["--target", "192.0.2.1"])
    assert args.retries == 1
