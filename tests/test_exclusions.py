"""Tests for --exclude / --exclude-file CIDR exclusion flags.

All tests use the ipaddress stdlib module and do not require network access.
"""

from __future__ import annotations

import ipaddress
import textwrap

import httpx
import pytest

from hellhound import cli
from hellhound.fingerprint import AuthCheck, Credential, Fingerprint, MatchCriteria
from hellhound.scanner import Scanner


# ------------------------------------------------------------------ helpers


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


# ------------------------------------------------------------------ parse_exclusions unit tests


def test_parse_exclusions_empty():
    result = Scanner.parse_exclusions()
    assert result == []


def test_parse_exclusions_single_ip():
    result = Scanner.parse_exclusions(exclude=["192.0.2.1"])
    assert len(result) == 1
    assert ipaddress.ip_address("192.0.2.1") in result[0]


def test_parse_exclusions_cidr():
    result = Scanner.parse_exclusions(exclude=["10.0.0.0/8"])
    assert len(result) == 1
    assert ipaddress.ip_address("10.1.2.3") in result[0]
    assert ipaddress.ip_address("192.0.2.1") not in result[0]


def test_parse_exclusions_multiple_entries():
    result = Scanner.parse_exclusions(exclude=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    assert len(result) == 3


def test_parse_exclusions_from_file(tmp_path):
    excl_file = tmp_path / "excl.txt"
    excl_file.write_text(
        textwrap.dedent("""\
            # this is a comment
            10.0.0.0/8

            # another comment
            172.16.0.0/12
            192.168.1.50
        """)
    )
    result = Scanner.parse_exclusions(exclude_file=str(excl_file))
    assert len(result) == 3
    assert ipaddress.ip_address("10.5.6.7") in result[0]
    assert ipaddress.ip_address("172.20.0.1") in result[1]
    assert ipaddress.ip_address("192.168.1.50") in result[2]


def test_parse_exclusions_file_blank_lines_and_comments_ignored(tmp_path):
    excl_file = tmp_path / "excl.txt"
    excl_file.write_text(
        textwrap.dedent("""\
            # header comment

            # another comment

            198.51.100.0/24

        """)
    )
    result = Scanner.parse_exclusions(exclude_file=str(excl_file))
    assert len(result) == 1


def test_parse_exclusions_combine_flag_and_file(tmp_path):
    excl_file = tmp_path / "excl.txt"
    excl_file.write_text("172.16.0.0/12\n")
    result = Scanner.parse_exclusions(exclude=["10.0.0.0/8"], exclude_file=str(excl_file))
    assert len(result) == 2


def test_parse_exclusions_invalid_entry_raises():
    with pytest.raises(ValueError):
        Scanner.parse_exclusions(exclude=["not-a-valid-cidr"])


def test_parse_exclusions_nonexistent_file_raises():
    with pytest.raises(OSError):
        Scanner.parse_exclusions(exclude_file="/nonexistent-path/excl.txt")


# ------------------------------------------------------------------ is_excluded unit tests


def test_is_excluded_single_ip_match():
    nets = Scanner.parse_exclusions(exclude=["192.0.2.5"])
    assert Scanner.is_excluded("192.0.2.5", nets) is True


def test_is_excluded_single_ip_no_match():
    nets = Scanner.parse_exclusions(exclude=["192.0.2.5"])
    assert Scanner.is_excluded("192.0.2.6", nets) is False


def test_is_excluded_cidr_match():
    nets = Scanner.parse_exclusions(exclude=["10.0.0.0/8"])
    assert Scanner.is_excluded("10.99.1.1", nets) is True


def test_is_excluded_cidr_no_match():
    nets = Scanner.parse_exclusions(exclude=["10.0.0.0/8"])
    assert Scanner.is_excluded("172.16.0.1", nets) is False


def test_is_excluded_hostname_never_excluded():
    """Bare hostnames cannot be matched to a CIDR; they are never excluded."""
    nets = Scanner.parse_exclusions(exclude=["10.0.0.0/8"])
    assert Scanner.is_excluded("mydevice.local", nets) is False


def test_is_excluded_no_exclusions():
    assert Scanner.is_excluded("10.0.0.1", []) is False


# ------------------------------------------------------------------ expand + exclude integration


def test_expand_targets_with_exclusion_filters_single_ip():
    """A /30 yields .1 and .2; exclude .1 → only .2 survives."""
    nets = Scanner.parse_exclusions(exclude=["203.0.113.1"])
    hosts = Scanner.expand_targets(["203.0.113.0/30"])
    filtered = [h for h in hosts if not Scanner.is_excluded(h, nets)]
    assert "203.0.113.1" not in filtered
    assert "203.0.113.2" in filtered


def test_expand_targets_with_cidr_exclusion_filters_all_matching():
    """Excluding the whole /30 leaves nothing."""
    nets = Scanner.parse_exclusions(exclude=["203.0.113.0/30"])
    hosts = Scanner.expand_targets(["203.0.113.0/30"])
    filtered = [h for h in hosts if not Scanner.is_excluded(h, nets)]
    assert filtered == []


def test_scan_skips_excluded_hosts():
    """scanner.scan() with an exclusion list must not scan excluded addresses."""
    import asyncio

    scanned: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        scanned.append(request.url.host)
        return httpx.Response(200, html="<html><head><title>Hikvision</title></head></html>")

    transport = httpx.MockTransport(handler)
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    exclusions = Scanner.parse_exclusions(exclude=["203.0.113.2"])
    asyncio.run(scanner.scan(["203.0.113.1", "203.0.113.2"], ports=[80], exclusions=exclusions))

    assert "203.0.113.1" in scanned
    assert "203.0.113.2" not in scanned


# ------------------------------------------------------------------ CLI integration


def test_cli_parser_accepts_exclude_flag():
    parser = cli.build_parser()
    args = parser.parse_args(["--target", "192.0.2.0/24", "--exclude", "192.0.2.5"])
    assert args.exclude == ["192.0.2.5"]


def test_cli_parser_accepts_exclude_flag_multiple():
    parser = cli.build_parser()
    args = parser.parse_args(
        ["--target", "192.0.2.0/24", "--exclude", "192.0.2.5", "--exclude", "10.0.0.0/8"]
    )
    assert args.exclude == ["192.0.2.5", "10.0.0.0/8"]


def test_cli_parser_accepts_exclude_file(tmp_path):
    excl_file = tmp_path / "excl.txt"
    excl_file.write_text("192.0.2.5\n")
    parser = cli.build_parser()
    args = parser.parse_args(["--target", "192.0.2.0/24", "--exclude-file", str(excl_file)])
    assert args.exclude_file == str(excl_file)


def test_cli_main_exclude_filters_target(monkeypatch, capsys):
    """CLI: excluded host is not in the scan targets passed to Scanner.scan."""
    captured_targets: list[list[str]] = []

    async def fake_scan(self, targets, ports, exclusions=None):
        # apply exclusions the same way the real scan() does
        hosts = Scanner.expand_targets(targets)
        if exclusions:
            hosts = [h for h in hosts if not Scanner.is_excluded(h, exclusions)]
        captured_targets.append(hosts)
        return []

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(
        ["--target", "203.0.113.0/30", "--exclude", "203.0.113.1"]
    )
    assert exit_code == 0
    assert captured_targets
    assert "203.0.113.1" not in captured_targets[0]
    assert "203.0.113.2" in captured_targets[0]


def test_cli_main_exclude_file(monkeypatch, capsys, tmp_path):
    """CLI: --exclude-file is loaded and applied."""
    excl_file = tmp_path / "excl.txt"
    excl_file.write_text("# comment\n203.0.113.1\n")

    captured_targets: list[list[str]] = []

    async def fake_scan(self, targets, ports, exclusions=None):
        hosts = Scanner.expand_targets(targets)
        if exclusions:
            hosts = [h for h in hosts if not Scanner.is_excluded(h, exclusions)]
        captured_targets.append(hosts)
        return []

    monkeypatch.setattr("hellhound.scanner.Scanner.scan", fake_scan)

    exit_code = cli.main(
        ["--target", "203.0.113.0/30", "--exclude-file", str(excl_file)]
    )
    assert exit_code == 0
    assert "203.0.113.1" not in captured_targets[0]
    assert "203.0.113.2" in captured_targets[0]


def test_cli_main_invalid_exclude_returns_error(monkeypatch, capsys):
    """CLI: invalid CIDR in --exclude prints an error and exits with code 2."""
    exit_code = cli.main(["--target", "192.0.2.0/24", "--exclude", "not-a-cidr"])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "error" in err.lower()
