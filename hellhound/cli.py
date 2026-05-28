"""hellhound command-line interface.

    hellhound --target 192.0.2.0/24 --ports 80,443 --fingerprint-set default --format json

Detection-only: hellhound reports IoT devices that still accept their
factory-default credentials. Use only against systems you are authorised to
test. See the ethical-use notice in README.md.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import json
import sys
from typing import TextIO

from . import __version__
from .fingerprint import load_fingerprint_set_with_dir
from .scanner import Finding, Scanner, ScanProgress

DEFAULT_PORTS = "80,443,8080,8443"

CSV_COLUMNS = [
    "host",
    "port",
    "scheme",
    "vendor",
    "model_class",
    "severity",
    "fingerprint_id",
    "default_creds",
    "username",
    "password",
    "cve",
    "evidence",
]

# Columns for the --list-fingerprints CSV view (inventory of the loaded set,
# not scan findings — distinct from CSV_COLUMNS above).
FINGERPRINT_LIST_COLUMNS = [
    "id",
    "vendor",
    "model_class",
    "severity",
    "auth_type",
    "auth_path",
    "default_credentials",
    "cve",
]


def _format_credentials(fp) -> str:
    """Render a fingerprint's default credentials as 'user:pass' pairs.

    A blank password renders as 'user:' so an empty-string default (common on
    cameras) stays visible. Pairs are separated by ';'.
    """
    return ";".join(f"{c.username}:{c.password}" for c in fp.credentials)


def format_fingerprint_list(fingerprints, fmt: str) -> str:
    """Render the loaded fingerprint database for ``--list-fingerprints``.

    This is an inventory view of the *capabilities* hellhound currently carries
    (after any ``--fingerprint-dir`` merge), not scan results. It lets an
    operator audit which device classes, vendors, severities and CVEs are
    covered, and confirm a custom set merged as expected — all without touching
    the network. ``sarif`` is not a meaningful inventory format and falls back
    to ``json``.
    """
    if fmt == "json" or fmt == "sarif":
        payload = {
            "summary": {"fingerprint_count": len(fingerprints)},
            "fingerprints": [
                {
                    "id": fp.id,
                    "vendor": fp.vendor,
                    "model_class": fp.model_class,
                    "severity": fp.severity,
                    "auth_type": fp.auth.type,
                    "auth_path": fp.auth.path,
                    "default_credentials": [
                        {"username": c.username, "password": c.password}
                        for c in fp.credentials
                    ],
                    "cve": list(fp.cve),
                }
                for fp in fingerprints
            ],
        }
        return json.dumps(payload, indent=2)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(FINGERPRINT_LIST_COLUMNS)
        for fp in fingerprints:
            writer.writerow(
                [
                    fp.id,
                    fp.vendor,
                    fp.model_class,
                    fp.severity,
                    fp.auth.type,
                    fp.auth.path,
                    _format_credentials(fp),
                    ";".join(fp.cve),
                ]
            )
        return buf.getvalue().rstrip("\r\n")

    # text
    lines: list[str] = [f"hellhound: {len(fingerprints)} fingerprint(s) loaded"]
    for fp in fingerprints:
        cve = f" [{', '.join(fp.cve)}]" if fp.cve else ""
        lines.append(
            f"[{fp.severity.upper()}] {fp.id}: {fp.vendor} ({fp.model_class}) "
            f"auth={fp.auth.type}{cve}"
        )
        lines.append(f"  default creds: {_format_credentials(fp) or '(none)'}")
    return "\n".join(lines)


def parse_ports(value: str) -> list[int]:
    """Parse a comma-separated port list into a list of ints."""
    ports: list[int] = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            port = int(chunk)
        except ValueError as exc:
            raise ValueError(f"invalid port: {chunk!r}") from exc
        if not (1 <= port <= 65535):
            raise ValueError(f"port out of range: {port}")
        ports.append(port)
    if not ports:
        raise ValueError("no valid ports provided")
    return ports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hellhound",
        description=(
            "Scan a CIDR range or host for known IoT devices and check whether "
            "they still accept factory-default credentials (detection-only)."
        ),
        epilog="Use only against systems you are explicitly authorised to test.",
    )
    parser.add_argument(
        "--target",
        "-t",
        action="append",
        metavar="CIDR|IP",
        help="Target to scan: a CIDR range (e.g. 192.0.2.0/24) or single IP/host. "
        "Repeat to scan multiple targets. Required unless --list-fingerprints "
        "is given.",
    )
    parser.add_argument(
        "--ports",
        "-p",
        default=DEFAULT_PORTS,
        metavar="LIST",
        help=f"Comma-separated ports to probe (default: {DEFAULT_PORTS}).",
    )
    parser.add_argument(
        "--fingerprint-set",
        "-f",
        default="default",
        metavar="NAME",
        help="Name of the fingerprint set to load from hellhound/fingerprints "
        "(default: default).",
    )
    parser.add_argument(
        "--fingerprint-dir",
        default=None,
        metavar="PATH",
        help="Directory holding a custom fingerprint set named '<set>.yaml' "
        "(matching --fingerprint-set). Custom entries override bundled ones "
        "by id; the rest are appended. Lets you maintain a private fingerprint "
        "set without patching hellhound.",
    )
    parser.add_argument(
        "--list-fingerprints",
        action="store_true",
        default=False,
        help="Inventory mode: print the loaded fingerprint database (after any "
        "--fingerprint-dir merge) and exit without scanning. Honours --format "
        "(json/text/csv) and --output-file. Use it to audit device-class, "
        "vendor, severity and CVE coverage, or to verify a custom set merged "
        "correctly. No target is required in this mode.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text", "csv", "sarif"],
        default="json",
        help="Output format (default: json). 'sarif' emits a SARIF 2.1.0 "
        "document for upload to GitHub code scanning and other SARIF consumers.",
    )
    parser.add_argument(
        "--output-file",
        "-o",
        default=None,
        metavar="PATH",
        help="Write output to PATH instead of stdout (default: stdout).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        metavar="SECONDS",
        help="Per-request timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=50,
        metavar="N",
        help="Maximum concurrent requests (default: 50).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=1,
        metavar="N",
        help="Total attempts per request before giving up (default: 1, a "
        "single try). Higher values retry transient connection failures with "
        "exponential backoff (0.5s x attempt), recovering false negatives from "
        "flaky IoT webservers.",
    )
    parser.add_argument(
        "--rate-limit",
        type=float,
        default=0.0,
        metavar="N",
        help="Cap outbound requests to N per second across the whole scan "
        "(0 = unlimited, the default). Seats above --concurrency: a leaky "
        "bucket paces requests so high concurrency never exceeds the rate. Use "
        "this to avoid overwhelming fragile embedded webservers (some cameras "
        "watchdog-reboot under burst load) or tripping IDS rules.",
    )
    parser.add_argument(
        "--exclude",
        "-e",
        action="append",
        default=[],
        metavar="CIDR|IP",
        help="Exclude a CIDR range or single IP from scanning. "
        "Repeat to exclude multiple ranges (e.g. --exclude 10.0.0.0/8 --exclude 172.16.0.0/12).",
    )
    parser.add_argument(
        "--exclude-file",
        metavar="PATH",
        default=None,
        help="Path to a file of CIDR/IP exclusions, one per line. "
        "Lines starting with '#' and blank lines are ignored.",
    )
    parser.add_argument(
        "--only-vulnerable",
        action="store_true",
        default=False,
        help="Digest mode: report only findings with confirmed default "
        "credentials. Suppresses matched-but-rotated findings to cut noise "
        "on large sweeps. Summary counts still reflect all matches.",
    )
    parser.add_argument(
        "--exit-code",
        type=int,
        default=0,
        metavar="N",
        help="Exit with code N when one or more confirmed default-credential "
        "exposures are found (default: 0, i.e. always exit 0 on a successful "
        "scan, the original behaviour). Set to a non-zero value (e.g. 1) to "
        "fail CI/CD pipelines or scripts when hellhound finds an exposed "
        "device: `hellhound -t 10.0.0.0/24 --exit-code 1 || alert`. Output is "
        "unchanged; only the process exit status is affected. Argument errors, "
        "bad input, and I/O failures still exit 2 regardless.",
    )
    progress_group = parser.add_mutually_exclusive_group()
    progress_group.add_argument(
        "--progress",
        action="store_true",
        default=None,
        help="Emit a live progress line to stderr (hosts scanned / total, "
        "findings so far) during the scan. Default: on when stderr is a TTY, "
        "off when redirected or piped. stdout output is never affected.",
    )
    progress_group.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=False,
        help="Suppress all stderr output including the progress line. Mutually "
        "exclusive with --progress.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"hellhound {__version__}",
    )
    return parser


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# Map hellhound severities onto the SARIF result level vocabulary.
# critical/high are actionable failures (error); medium is a warning; anything
# else (low/info/unknown) is a note.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def _sarif_level(severity: str) -> str:
    return _SARIF_LEVEL.get((severity or "").lower(), "note")


def format_sarif(findings: list[Finding]) -> str:
    """Render findings as a SARIF 2.1.0 document.

    SARIF (Static Analysis Results Interchange Format) 2.1.0 is the OASIS
    standard accepted by GitHub code scanning, GitLab, and most enterprise
    security platforms. hellhound emits one ``result`` per finding with
    confirmed default credentials (``default_creds is True``) — these are the
    actionable exposures a SARIF consumer cares about. Matched-but-rotated
    findings are not vulnerabilities and are intentionally omitted.

    Each result encodes the device host/port as a location URI, maps the
    fingerprint severity onto the SARIF ``level`` vocabulary, and carries the
    associated CVE identifiers as result tags.
    """
    flagged = [f for f in findings if f.default_creds]

    # Build a stable rule per distinct fingerprint so SARIF consumers can group
    # results and surface a description.
    rules: list[dict] = []
    rule_index: dict[str, int] = {}
    for f in flagged:
        if f.fingerprint_id in rule_index:
            continue
        rule_index[f.fingerprint_id] = len(rules)
        rules.append(
            {
                "id": f.fingerprint_id,
                "name": f"{f.vendor} default credentials",
                "shortDescription": {
                    "text": f"{f.vendor} {f.model_class} accepts factory-default credentials"
                },
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
            }
        )

    results: list[dict] = []
    for f in flagged:
        result: dict = {
            "ruleId": f.fingerprint_id,
            "ruleIndex": rule_index[f.fingerprint_id],
            "level": _sarif_level(f.severity),
            "message": {"text": f.evidence},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"{f.scheme}://{f.host}:{f.port}/"}
                    }
                }
            ],
        }
        if f.cve:
            result["properties"] = {"cve": list(f.cve), "tags": list(f.cve)}
        results.append(result)

    document = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hellhound",
                        "informationUri": "https://github.com/bugsyhewitt/hellhound",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2)


def _render(findings: list[Finding], fmt: str, only_vulnerable: bool = False) -> str:
    """Render findings to a string in the requested format.

    When *only_vulnerable* is True (digest mode), the rendered findings list is
    filtered to entries with confirmed default credentials. The summary counts
    always reflect the full match set so the operator still sees how many
    devices matched a fingerprint versus how many were exposed.
    """
    flagged = [f for f in findings if f.default_creds]
    # The displayed findings are the digest subset when requested.
    shown = flagged if only_vulnerable else findings
    if fmt == "sarif":
        # SARIF reports vulnerabilities only; --only-vulnerable is implied and
        # the (verbose) hellhound summary block has no SARIF equivalent.
        return format_sarif(findings)

    if fmt == "json":
        payload = {
            "summary": {
                "devices_matched": len(findings),
                "devices_with_default_creds": len(flagged),
                "only_vulnerable": only_vulnerable,
            },
            "findings": [f.to_dict() for f in shown],
        }
        return json.dumps(payload, indent=2)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(CSV_COLUMNS)
        for f in shown:
            cred = f.matched_credential
            writer.writerow(
                [
                    f.host,
                    f.port,
                    f.scheme,
                    f.vendor,
                    f.model_class,
                    f.severity,
                    f.fingerprint_id,
                    "true" if f.default_creds else "false",
                    cred.username if cred else "",
                    cred.password if cred else "",
                    ";".join(f.cve),
                    f.evidence,
                ]
            )
        # csv writes its own line terminators; drop the trailing newline so the
        # string form matches the text/json convention (no trailing blank line).
        return buf.getvalue().rstrip("\r\n")

    # text
    lines: list[str] = []
    lines.append(f"hellhound: {len(findings)} device(s) matched, {len(flagged)} with default creds")
    for f in shown:
        status = "DEFAULT-CREDS" if f.default_creds else "matched (creds rotated)"
        cred = f"  creds: {f.matched_credential}" if f.matched_credential else ""
        lines.append(
            f"[{f.severity.upper()}] {f.host}:{f.port} {f.vendor} "
            f"({f.model_class}) -> {status}{cred}"
        )
        if f.cve:
            lines.append(f"  cve: {', '.join(f.cve)}")
        lines.append(f"  evidence: {f.evidence}")
    return "\n".join(lines)


def format_output(
    findings: list[Finding],
    fmt: str,
    stream: TextIO | None = None,
    only_vulnerable: bool = False,
) -> str | None:
    """Format findings.

    With no ``stream``, return the formatted text as a string (back-compatible).
    With a ``stream``, write the formatted text (plus a trailing newline) to it
    and return ``None``.

    When *only_vulnerable* is True, the rendered findings are restricted to
    confirmed default-credential exposures (digest mode); summary counts are
    unaffected.
    """
    rendered = _render(findings, fmt, only_vulnerable=only_vulnerable)
    if stream is None:
        return rendered
    stream.write(rendered)
    stream.write("\n")
    return None


def resolve_progress_enabled(
    progress_flag: bool | None, quiet: bool, stream: TextIO | None = None
) -> bool:
    """Decide whether to emit the progress line.

    ``--quiet`` always wins (no stderr at all). An explicit ``--progress``
    forces it on. With neither flag set (``progress_flag is None``), progress
    auto-enables only when *stream* (stderr) is an interactive TTY, so piped or
    redirected runs stay silent and machine-friendly.
    """
    if quiet:
        return False
    if progress_flag:
        return True
    stream = stream if stream is not None else sys.stderr
    isatty = getattr(stream, "isatty", None)
    return bool(isatty()) if callable(isatty) else False


def make_progress_callback(stream: TextIO | None = None):
    """Build a callback that writes a single rewriting progress line to *stream*.

    The line is carriage-return prefixed so each update overwrites the previous
    one in a terminal, keeping the scan to one tidy status line. It writes to
    stderr by default so stdout stays a clean machine-readable stream.
    """
    out = stream if stream is not None else sys.stderr

    def callback(progress: ScanProgress) -> None:
        line = (
            f"\rhellhound: {progress.hosts_done}/{progress.hosts_total} hosts "
            f"scanned, {progress.findings_with_default_creds} with default creds"
        )
        out.write(line)
        if progress.hosts_done >= progress.hosts_total:
            # finish the line so it doesn't get clobbered by the final output
            out.write("\n")
        out.flush()

    return callback


def resolve_exit_code(findings: list[Finding], exit_code_when_found: int) -> int:
    """Decide the process exit code for a completed scan.

    Returns ``exit_code_when_found`` when at least one finding has confirmed
    default credentials (``default_creds is True``) and the operator opted into
    findings-based exit status (a non-zero ``exit_code_when_found``). Otherwise
    returns ``0``.

    The default of ``0`` preserves hellhound's original contract — a successful
    scan always exits 0 regardless of what it found. Passing a non-zero value
    turns a confirmed exposure into a non-zero exit so the tool can gate a CI/CD
    pipeline or a shell script. This decision is intentionally independent of
    ``--only-vulnerable`` (which only filters *displayed* findings, not the
    underlying match set) so the exit signal is stable across output modes.
    """
    if exit_code_when_found == 0:
        return 0
    if any(f.default_creds for f in findings):
        return exit_code_when_found
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        fingerprints = load_fingerprint_set_with_dir(
            args.fingerprint_set,
            fingerprint_dir=args.fingerprint_dir,
        )
    except FileNotFoundError as exc:
        print(f"error: unknown fingerprint set: {exc}", file=sys.stderr)
        return 2

    # Inventory mode: print the loaded fingerprint database and exit. No target
    # or network access required — this honours --fingerprint-dir merges so an
    # operator can audit and verify their effective coverage before scanning.
    if args.list_fingerprints:
        rendered = format_fingerprint_list(fingerprints, args.format)
        if args.output_file is None:
            print(rendered)
            return 0
        try:
            with open(args.output_file, "w", newline="", encoding="utf-8") as fh:
                fh.write(rendered)
                fh.write("\n")
        except OSError as exc:
            print(f"error: could not write output file: {exc}", file=sys.stderr)
            return 2
        return 0

    if not args.target:
        print(
            "error: --target is required (or use --list-fingerprints to "
            "inspect the fingerprint database)",
            file=sys.stderr,
        )
        return 2

    try:
        exclusions = Scanner.parse_exclusions(
            exclude=args.exclude or [],
            exclude_file=args.exclude_file,
        )
    except (ValueError, OSError) as exc:
        print(f"error: invalid exclusion: {exc}", file=sys.stderr)
        return 2

    scanner = Scanner(
        fingerprints=fingerprints,
        timeout=args.timeout,
        concurrency=args.concurrency,
        retries=args.retries,
        rate_limit=args.rate_limit,
    )

    progress_callback = None
    if resolve_progress_enabled(args.progress, args.quiet):
        progress_callback = make_progress_callback()

    findings = asyncio.run(
        scanner.scan(
            args.target,
            ports,
            exclusions=exclusions,
            progress_callback=progress_callback,
        )
    )

    if args.output_file is None:
        # stdout: csv module wants newline="" but sys.stdout is already managed;
        # render to a string and print so behaviour is unchanged for json/text.
        print(
            format_output(
                findings, args.format, only_vulnerable=args.only_vulnerable
            )
        )
        return resolve_exit_code(findings, args.exit_code)

    try:
        # newline="" lets the csv module control line terminators (avoids the
        # classic doubled-newline-on-Windows issue); harmless for json/text.
        with open(args.output_file, "w", newline="", encoding="utf-8") as fh:
            format_output(
                findings,
                args.format,
                stream=fh,
                only_vulnerable=args.only_vulnerable,
            )
    except OSError as exc:
        print(f"error: could not write output file: {exc}", file=sys.stderr)
        return 2
    return resolve_exit_code(findings, args.exit_code)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
