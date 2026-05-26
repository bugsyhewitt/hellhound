"""hellhound command-line interface.

    hellhound --target 192.0.2.0/24 --ports 80,443 --fingerprint-set default --format json

Detection-only: hellhound reports IoT devices that still accept their
factory-default credentials. Use only against systems you are authorised to
test. See the ethical-use notice in README.md.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import __version__
from .fingerprint import load_fingerprint_set
from .scanner import Finding, Scanner

DEFAULT_PORTS = "80,443,8080,8443"


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
        required=True,
        metavar="CIDR|IP",
        help="Target to scan: a CIDR range (e.g. 192.0.2.0/24) or single IP/host. "
        "Repeat to scan multiple targets.",
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
        "--format",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json).",
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
        "--version",
        action="version",
        version=f"hellhound {__version__}",
    )
    return parser


def format_output(findings: list[Finding], fmt: str) -> str:
    flagged = [f for f in findings if f.default_creds]
    if fmt == "json":
        payload = {
            "summary": {
                "devices_matched": len(findings),
                "devices_with_default_creds": len(flagged),
            },
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, indent=2)

    # text
    lines: list[str] = []
    lines.append(f"hellhound: {len(findings)} device(s) matched, {len(flagged)} with default creds")
    for f in findings:
        status = "DEFAULT-CREDS" if f.default_creds else "matched (creds rotated)"
        cred = f"  creds: {f.matched_credential}" if f.matched_credential else ""
        lines.append(
            f"[{f.severity.upper()}] {f.host}:{f.port} {f.vendor} "
            f"({f.model_class}) -> {status}{cred}"
        )
        lines.append(f"  evidence: {f.evidence}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        fingerprints = load_fingerprint_set(args.fingerprint_set)
    except FileNotFoundError as exc:
        print(f"error: unknown fingerprint set: {exc}", file=sys.stderr)
        return 2

    scanner = Scanner(
        fingerprints=fingerprints,
        timeout=args.timeout,
        concurrency=args.concurrency,
    )

    findings = asyncio.run(scanner.scan(args.target, ports))
    print(format_output(findings, args.format))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
