"""Smoke test (criterion 6).

A fast, no-network sanity check that the package imports, the CLI parses, the
fingerprint database loads with the required minimum, and the headline
Hikvision detection path works end to end through the public API.
"""

import asyncio

import httpx

import hellhound
from hellhound.cli import build_parser, format_output, parse_ports
from hellhound.fingerprint import Credential, load_fingerprint_set
from hellhound.scanner import Scanner


def test_package_imports_with_version():
    assert hellhound.__version__ == "0.1.0"


def test_cli_parser_constructs():
    parser = build_parser()
    args = parser.parse_args(["--target", "192.0.2.1", "--ports", "80"])
    assert args.target == ["192.0.2.1"]
    assert parse_ports(args.ports) == [80]


def test_database_meets_minimum_size():
    fingerprints = load_fingerprint_set("default")
    assert len(fingerprints) >= 10


def test_end_to_end_hikvision_detection_and_output():
    fingerprints = load_fingerprint_set("default")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                200,
                html="<html><head><title>Hikvision Network Camera</title></head></html>",
            )
        if request.url.path == "/ISAPI/Security/userCheck":
            if request.headers.get("authorization") == "Basic YWRtaW46MTIzNDU=":
                return httpx.Response(200, text="<statusValue>200</statusValue>")
            return httpx.Response(401)
        return httpx.Response(404)

    scanner = Scanner(fingerprints=fingerprints, transport=httpx.MockTransport(handler))
    findings = asyncio.run(scanner.scan_host("203.0.113.10", ports=[80]))

    flagged = [f for f in findings if f.default_creds]
    assert flagged
    assert flagged[0].vendor == "Hikvision"
    assert flagged[0].matched_credential == Credential("admin", "12345")

    # output formatting must round-trip both formats
    json_out = format_output(findings, "json")
    text_out = format_output(findings, "text")
    assert "Hikvision" in json_out
    assert "Hikvision" in text_out
