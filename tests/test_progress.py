"""Tests for async progress reporting (POST_V01 Rank 10).

When scanning a /16 or /24, hellhound prints nothing until every result is
ready. ``--progress`` emits a live status line to stderr (hosts scanned / total,
findings so far) so operators have feedback on long sweeps; ``--quiet``
suppresses all stderr output. Progress auto-enables only when stderr is a TTY so
piped/redirected runs stay machine-friendly.

These tests use httpx.MockTransport so they run with no network and no Docker,
and a fake stream to capture progress output deterministically.
"""

import asyncio
import io

import httpx

from hellhound.cli import (
    build_parser,
    main,
    make_progress_callback,
    resolve_progress_enabled,
)
from hellhound.fingerprint import AuthCheck, Credential, Fingerprint, MatchCriteria
from hellhound.scanner import ScanProgress, Scanner


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


def no_match_handler():
    """A MockTransport handler whose landing page never matches a fingerprint."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, html="<html><head><title>nothing</title></head></html>")

    return handler


class FakeTTY(io.StringIO):
    """A StringIO that reports itself as a TTY (or not) for progress detection."""

    def __init__(self, isatty: bool = True) -> None:
        super().__init__()
        self._isatty = isatty

    def isatty(self) -> bool:
        return self._isatty


# ----------------------------------------------------------- scanner callback


def test_scan_invokes_progress_callback_per_host():
    """The callback fires once per scanned host with a monotonic done count."""
    transport = httpx.MockTransport(hikvision_handler())
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    seen: list[ScanProgress] = []
    run(
        scanner.scan(
            ["203.0.113.0/30"],  # /30 -> 2 usable hosts
            ports=[80],
            progress_callback=seen.append,
        )
    )

    assert len(seen) == 2
    # hosts_done advances 1..N and the total is the post-expansion host count
    assert [p.hosts_done for p in seen] == [1, 2]
    assert all(p.hosts_total == 2 for p in seen)
    # both hosts matched and authenticated -> running flagged tally reaches 2
    assert seen[-1].findings_with_default_creds == 2


def test_progress_flagged_count_excludes_non_default_creds():
    """The running tally counts only confirmed default-credential findings."""
    transport = httpx.MockTransport(no_match_handler())
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    seen: list[ScanProgress] = []
    run(scanner.scan(["203.0.113.5"], ports=[80], progress_callback=seen.append))

    assert len(seen) == 1
    assert seen[0].hosts_done == 1
    assert seen[0].hosts_total == 1
    assert seen[0].findings_with_default_creds == 0


def test_scan_without_callback_still_works():
    """Omitting the callback preserves the original (no-progress) behaviour."""
    transport = httpx.MockTransport(hikvision_handler())
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)

    findings = run(scanner.scan(["203.0.113.5"], ports=[80]))

    assert len(findings) == 1
    assert findings[0].default_creds is True


def test_progress_respects_exclusions_in_total():
    """Excluded hosts are dropped before counting, so the total reflects scope."""
    transport = httpx.MockTransport(hikvision_handler())
    scanner = Scanner(fingerprints=[hikvision_fingerprint()], transport=transport)
    exclusions = Scanner.parse_exclusions(exclude=["203.0.113.1"])

    seen: list[ScanProgress] = []
    run(
        scanner.scan(
            ["203.0.113.0/30"],  # 2 usable: .1 and .2; .1 excluded
            ports=[80],
            exclusions=exclusions,
            progress_callback=seen.append,
        )
    )

    assert len(seen) == 1
    assert seen[0].hosts_total == 1


# -------------------------------------------------------- enablement decision


def test_quiet_always_disables_progress():
    """--quiet wins over everything, even an explicit --progress / a TTY."""
    tty = FakeTTY(isatty=True)
    assert resolve_progress_enabled(progress_flag=True, quiet=True, stream=tty) is False
    assert resolve_progress_enabled(progress_flag=None, quiet=True, stream=tty) is False


def test_explicit_progress_enables_even_when_not_a_tty():
    """--progress forces progress on regardless of TTY state."""
    not_tty = FakeTTY(isatty=False)
    assert resolve_progress_enabled(progress_flag=True, quiet=False, stream=not_tty) is True


def test_progress_auto_enables_only_on_a_tty():
    """With no flags, progress follows whether stderr is interactive."""
    assert resolve_progress_enabled(None, False, stream=FakeTTY(isatty=True)) is True
    assert resolve_progress_enabled(None, False, stream=FakeTTY(isatty=False)) is False


# -------------------------------------------------------------- callback render


def test_progress_callback_writes_status_line():
    """The callback writes a CR-prefixed status line to its stream."""
    out = io.StringIO()
    callback = make_progress_callback(stream=out)

    callback(ScanProgress(hosts_done=3, hosts_total=10, findings_with_default_creds=1))

    text = out.getvalue()
    assert "\rhellhound: 3/10 hosts scanned, 1 with default creds" in text
    # not the final host yet -> no trailing newline
    assert not text.endswith("\n")


def test_progress_callback_finishes_line_on_last_host():
    """On the final host the line is terminated so it isn't clobbered."""
    out = io.StringIO()
    callback = make_progress_callback(stream=out)

    callback(ScanProgress(hosts_done=10, hosts_total=10, findings_with_default_creds=2))

    text = out.getvalue()
    assert "10/10 hosts scanned, 2 with default creds" in text
    assert text.endswith("\n")


# ----------------------------------------------------------------------- cli


def test_cli_progress_and_quiet_flags_parsed():
    parser = build_parser()

    args = parser.parse_args(["--target", "192.0.2.1", "--progress"])
    assert args.progress is True
    assert args.quiet is False

    args = parser.parse_args(["--target", "192.0.2.1", "--quiet"])
    assert args.quiet is True
    assert args.progress is None

    # default: neither set
    args = parser.parse_args(["--target", "192.0.2.1"])
    assert args.progress is None
    assert args.quiet is False


def test_cli_progress_and_quiet_are_mutually_exclusive():
    parser = build_parser()
    import pytest

    with pytest.raises(SystemExit):
        parser.parse_args(["--target", "192.0.2.1", "--progress", "--quiet"])


def test_main_quiet_emits_no_progress_to_stderr(monkeypatch, capsys):
    """--quiet produces stdout findings but no stderr progress line."""
    transport = httpx.MockTransport(hikvision_handler())

    class PatchedScanner(Scanner):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("hellhound.cli.Scanner", PatchedScanner)

    rc = main(["--target", "203.0.113.5", "--ports", "80", "--quiet"])
    assert rc == 0

    captured = capsys.readouterr()
    assert "hellhound:" not in captured.err
    assert "203.0.113.5" in captured.out


def test_main_progress_emits_status_line_to_stderr(monkeypatch, capsys):
    """--progress writes a status line to stderr; stdout stays clean JSON."""
    transport = httpx.MockTransport(hikvision_handler())

    class PatchedScanner(Scanner):
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr("hellhound.cli.Scanner", PatchedScanner)

    rc = main(["--target", "203.0.113.5", "--ports", "80", "--progress"])
    assert rc == 0

    captured = capsys.readouterr()
    assert "1/1 hosts scanned" in captured.err
    # stdout remains the machine-readable findings document
    assert "203.0.113.5" in captured.out
    assert "hellhound: 1/1" not in captured.out
