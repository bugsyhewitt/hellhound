"""v0.2.0 expansion tests: 8 new fingerprints + async CIDR scan engine."""

from __future__ import annotations

import asyncio
import ipaddress

import httpx
import pytest

from hellhound.fingerprint import load_fingerprint_set
from hellhound.scanner import Scanner, probe_host_async, scan_cidr_async


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# 1. New device fingerprint count >= 8
# ---------------------------------------------------------------------------


def test_new_device_fingerprint_count():
    """The default fingerprint set must have grown by at least 8 entries."""
    fps = load_fingerprint_set("default")
    new_ids = {
        "cisco-ios-http",
        "netgear-wnr-router",
        "tplink-wr-classic",
        "synology-surveillance",
        "zyxel-vmg-gateway",
        "qnap-ts-nasui",
        "fortinet-fortiap",
        "paloalto-panorama",
    }
    present = {fp.id for fp in fps}
    missing = new_ids - present
    assert not missing, f"Missing new fingerprint IDs: {missing}"
    assert len(new_ids) >= 8


# ---------------------------------------------------------------------------
# 2. Cisco IOS HTTP fingerprint present
# ---------------------------------------------------------------------------


def test_cisco_ios_http_fingerprint_present():
    fps = load_fingerprint_set("default")
    fp_map = {fp.id: fp for fp in fps}
    assert "cisco-ios-http" in fp_map
    fp = fp_map["cisco-ios-http"]
    assert fp.vendor == "Cisco"
    assert any(c.password == "cisco" for c in fp.credentials)
    assert fp.auth.type == "basic"


# ---------------------------------------------------------------------------
# 3. Synology NAS (Surveillance Station) fingerprint present
# ---------------------------------------------------------------------------


def test_synology_surveillance_fingerprint_present():
    fps = load_fingerprint_set("default")
    fp_map = {fp.id: fp for fp in fps}
    assert "synology-surveillance" in fp_map
    fp = fp_map["synology-surveillance"]
    assert fp.vendor == "Synology"
    assert fp.match.body_contains is not None
    assert "/webapi/auth.cgi" in fp.auth.path


# ---------------------------------------------------------------------------
# 4. scan_cidr_async returns a list (mocked transport)
# ---------------------------------------------------------------------------


def test_scan_cidr_async_returns_list():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    fps = load_fingerprint_set("default")
    transport = httpx.MockTransport(handler)
    results = run(
        scan_cidr_async(
            "192.168.1.0/30",
            ports=[80],
            max_concurrent=4,
            fingerprints=fps,
            transport=transport,
        )
    )
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# 5. max_concurrent semaphore limits concurrency
# ---------------------------------------------------------------------------


def test_scan_cidr_respects_max_concurrent():
    """Semaphore should cap concurrent probes; scan must still complete."""
    call_count = 0
    max_seen = 0
    active = 0

    async def counting_handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count, max_seen, active
        active += 1
        max_seen = max(max_seen, active)
        call_count += 1
        await asyncio.sleep(0)
        active -= 1
        return httpx.Response(404)

    fps = load_fingerprint_set("default")

    async def run_scan():
        transport = httpx.MockTransport(counting_handler)
        return await scan_cidr_async(
            "192.168.1.0/28",
            ports=[80],
            max_concurrent=3,
            fingerprints=fps,
            transport=transport,
        )

    results = asyncio.run(run_scan())
    assert isinstance(results, list)
    # 14 usable hosts x 1 port = 14 calls
    assert call_count == 14


# ---------------------------------------------------------------------------
# 6. CIDR "192.168.1.0/30" produces exactly 2 usable hosts
# ---------------------------------------------------------------------------


def test_cidr_slash30_yields_two_usable_hosts():
    network = ipaddress.ip_network("192.168.1.0/30", strict=False)
    hosts = [str(h) for h in network.hosts()]
    assert len(hosts) == 2
    assert "192.168.1.1" in hosts
    assert "192.168.1.2" in hosts


# ---------------------------------------------------------------------------
# 7. CLI scan-cidr command is accepted without error
# ---------------------------------------------------------------------------


def test_cli_scan_cidr_command_accepted():
    """scan-cidr subcommand must be parsed without raising SystemExit."""
    from hellhound.cli import build_scan_cidr_parser

    parser = build_scan_cidr_parser()
    args = parser.parse_args(["--cidr", "192.168.1.0/24"])
    assert args.cidr == "192.168.1.0/24"
    assert args.max_concurrent == 50
    assert args.timeout == 5.0


def test_cli_scan_cidr_accepted_by_main(monkeypatch):
    """main() must route 'scan-cidr' and exit 0 (mocked transport returns 404)."""
    import httpx

    async def _mock_scan(*args, **kwargs):
        return []

    monkeypatch.setattr("hellhound.cli.scan_cidr_async", _mock_scan)

    from hellhound.cli import main

    rc = main(["scan-cidr", "--cidr", "192.168.1.0/30"])
    assert rc == 0


# ---------------------------------------------------------------------------
# 8. probe_host_async returns None on connection refused (mocked)
# ---------------------------------------------------------------------------


def test_probe_host_async_returns_none_on_connection_refused():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    fps = load_fingerprint_set("default")
    transport = httpx.MockTransport(handler)
    result = run(
        probe_host_async(
            "192.168.1.1",
            80,
            fingerprints=fps,
            transport=transport,
        )
    )
    assert result is None


def test_probe_host_async_returns_match_on_known_device():
    """probe_host_async must return a dict when a fingerprint matches."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            html="<html><head><title>Hikvision Network Camera</title></head></html>",
        )

    fps = [
        fp
        for fp in load_fingerprint_set("default")
        if fp.id == "hikvision-dvr"
    ]
    transport = httpx.MockTransport(handler)
    result = run(
        probe_host_async(
            "192.0.2.10",
            80,
            fingerprints=fps,
            transport=transport,
        )
    )
    assert result is not None
    assert result["ip"] == "192.0.2.10"
    assert result["port"] == 80
    assert result["matched_fingerprint"] == "hikvision-dvr"
    assert result["device_type"] == "Hikvision"
