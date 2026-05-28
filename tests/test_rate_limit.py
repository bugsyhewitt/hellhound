"""Tests for the requests-per-second rate cap (POST_V01 Rank 8).

A high ``--concurrency`` can overwhelm fragile embedded webservers or trip IDS
rules. ``--rate-limit N`` seats a leaky-bucket throttle above the concurrency
semaphore so no more than N requests fire per second across the whole scan.

These tests drive a fake monotonic clock and a fake ``asyncio.sleep`` so request
pacing is asserted deterministically without real wall-clock delays. They use
httpx.MockTransport so they run with no network and no Docker.
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


def hikvision_handler():
    """A MockTransport handler: landing page matches, default creds accepted."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
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

    return handler


class FakeClock:
    """A controllable monotonic clock that advances when sleep() is awaited.

    Installing this for both ``time.monotonic`` and ``asyncio.sleep`` lets the
    throttle's pacing be asserted without real delays: every sleep records its
    duration and advances the virtual clock by exactly that amount.
    """

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        # record only the throttle's own waits (positive durations)
        self.sleeps.append(seconds)
        if seconds > 0:
            self.now += seconds


def install_clock(monkeypatch) -> FakeClock:
    clock = FakeClock()
    monkeypatch.setattr("hellhound.scanner.time.monotonic", clock.monotonic)
    monkeypatch.setattr("hellhound.scanner.asyncio.sleep", clock.sleep)
    return clock


# --------------------------------------------------------------------- config


def test_rate_limit_zero_disables_throttle():
    """The default rate_limit=0 sets no minimum interval (no-op throttle)."""
    scanner = Scanner(fingerprints=[], rate_limit=0.0)
    assert scanner._min_interval == 0.0


def test_rate_limit_computes_min_interval():
    """rate_limit=N yields a minimum spacing of 1/N seconds between requests."""
    scanner = Scanner(fingerprints=[], rate_limit=4.0)
    assert scanner._min_interval == 0.25
    scanner = Scanner(fingerprints=[], rate_limit=10.0)
    assert scanner._min_interval == 0.1


def test_negative_rate_limit_is_clamped():
    """A negative rate is clamped to 0 (unlimited)."""
    scanner = Scanner(fingerprints=[], rate_limit=-5.0)
    assert scanner._rate_limit == 0.0
    assert scanner._min_interval == 0.0


# --------------------------------------------------------------------- pacing


def test_throttle_paces_requests(monkeypatch):
    """With a rate cap, sequential requests are spaced by the min interval.

    Two ports on one host means at least two landing-page requests; the second
    must wait one interval (here 0.5s for a 2 req/s cap) behind the first.
    """
    clock = install_clock(monkeypatch)
    transport = httpx.MockTransport(hikvision_handler())
    scanner = Scanner(
        fingerprints=[hikvision_fingerprint()],
        transport=transport,
        rate_limit=2.0,  # 0.5s between requests
        concurrency=50,
    )

    findings = run(scanner.scan_host("203.0.113.10", ports=[80, 443]))

    # both ports matched and authenticated
    assert len(findings) == 2
    assert all(f.default_creds for f in findings)

    # The first request fires immediately (wait 0); every subsequent request
    # waits exactly one interval. There are 4 requests total (2 landing pages +
    # 2 auth checks), so 3 of them are paced at 0.5s.
    positive = [s for s in clock.sleeps if s > 0]
    assert positive == [0.5, 0.5, 0.5]


def test_no_throttle_means_no_sleeps(monkeypatch):
    """Without a rate cap, the throttle never sleeps (original behaviour)."""
    clock = install_clock(monkeypatch)
    transport = httpx.MockTransport(hikvision_handler())
    scanner = Scanner(
        fingerprints=[hikvision_fingerprint()],
        transport=transport,
        rate_limit=0.0,
    )

    findings = run(scanner.scan_host("203.0.113.10", ports=[80]))

    assert len(findings) == 1
    assert clock.sleeps == []


def test_throttle_does_not_overpace_when_clock_advances(monkeypatch):
    """If real time already elapsed past the slot, the next request fires now.

    The leaky bucket only delays when requests arrive faster than the cap; once
    the reserved slot is in the past it issues immediately (wait 0).
    """
    clock = install_clock(monkeypatch)
    transport = httpx.MockTransport(hikvision_handler())
    scanner = Scanner(
        fingerprints=[hikvision_fingerprint()],
        transport=transport,
        rate_limit=2.0,
    )

    # first request: reserves slot, no wait
    run(scanner._throttle())
    assert clock.sleeps == []

    # advance the clock well past the reserved interval
    clock.now += 10.0

    # next request should not wait — the slot is far in the past
    run(scanner._throttle())
    assert [s for s in clock.sleeps if s > 0] == []


# ----------------------------------------------------------------------- cli


def test_cli_rate_limit_flag_parsed():
    from hellhound.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["--target", "192.0.2.1", "--rate-limit", "5"])
    assert args.rate_limit == 5.0
    # default is unlimited
    args = parser.parse_args(["--target", "192.0.2.1"])
    assert args.rate_limit == 0.0
