"""Shared test helpers for fingerprint tranche mock-transport tests.

Every Phase 2 tranche test file drives the same scaffold: load the bundled
fingerprint set once, isolate a single fingerprint, run the Scanner against an
``httpx.MockTransport``, and assert the expected findings shape. These helpers
live here so the scaffold is defined in exactly one place.

Usage in a tranche test file::

    import httpx
    from hellhound.fingerprint import Credential
    from _fingerprint_helpers import (
        BUNDLED, assert_flagged, basic_creds, form_field, fp, scan_one,
    )
"""

from __future__ import annotations

import asyncio
import base64
from urllib.parse import parse_qs

import httpx

from hellhound.fingerprint import Credential, load_fingerprint_set
from hellhound.scanner import Scanner

# Load once at module import time; Python's module cache means all tranche
# test files that import this module share the single parsed result, avoiding
# repeated YAML parsing across 20+ test modules.
BUNDLED = load_fingerprint_set("default")


def run(coro):
    return asyncio.run(coro)


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
