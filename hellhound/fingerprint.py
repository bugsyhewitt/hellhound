"""Fingerprint data model and YAML database loading.

A fingerprint describes how to recognise a class of IoT device from its
HTTP/HTTPS surface, and which factory-default credentials to check against it.

The on-disk format is a YAML file under ``hellhound/fingerprints/`` with a
top-level ``fingerprints`` list. Each entry looks like::

    - id: hikvision-dvr
      vendor: Hikvision
      model_class: DVR/NVR/IP Camera
      severity: critical
      match:
        path: /
        http_title: Hikvision
        body_contains: doc/page/login.asp   # optional
        header_contains:                      # optional
          server: App-webs
        status_code: 200                      # optional
      default_credentials:
        - {username: admin, password: "12345"}
      auth:
        type: basic            # one of: basic | form
        path: /ISAPI/Security/userCheck
        # form auth also accepts: method, username_field, password_field,
        # success_status, failure_body_contains

[Worker decision: match criteria use AND semantics across the specified
fields. An entry with no positive criteria never matches, so a malformed
fingerprint cannot silently flag every host on the network.]
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

FINGERPRINTS_DIR = Path(__file__).resolve().parent / "fingerprints"

VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


@dataclass(frozen=True)
class Credential:
    """A username/password pair to test against a device."""

    username: str
    password: str

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.username}:{self.password}"


@dataclass(frozen=True)
class MatchCriteria:
    """Conditions a probed response must satisfy to match a fingerprint.

    All specified fields must match (logical AND). A criteria object with no
    positive condition is considered non-meaningful and never matches.
    """

    path: str = "/"
    http_title: str | None = None
    body_contains: str | None = None
    header_contains: dict[str, str] = field(default_factory=dict)
    status_code: int | None = None

    def is_meaningful(self) -> bool:
        """True if at least one positive match condition is set."""
        return bool(self.http_title or self.body_contains or self.header_contains)

    def matches(
        self,
        *,
        status: int,
        title: str,
        body: str,
        headers: dict[str, str],
    ) -> bool:
        if not self.is_meaningful():
            return False

        if self.status_code is not None and status != self.status_code:
            return False

        if self.http_title is not None:
            if self.http_title.lower() not in (title or "").lower():
                return False

        if self.body_contains is not None:
            if self.body_contains.lower() not in (body or "").lower():
                return False

        if self.header_contains:
            lowered = {k.lower(): (v or "") for k, v in (headers or {}).items()}
            for name, needle in self.header_contains.items():
                value = lowered.get(name.lower())
                if value is None or needle.lower() not in value.lower():
                    return False

        return True


@dataclass(frozen=True)
class AuthCheck:
    """How to verify a credential against a matched device.

    ``type`` is ``basic`` (HTTP Basic auth) or ``form`` (HTML form POST).
    """

    type: str = "basic"
    path: str = "/"
    method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    success_status: tuple[int, ...] = (200,)
    failure_body_contains: str | None = None
    extra_fields: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Fingerprint:
    """A device-class fingerprint plus its default-credential check."""

    id: str
    vendor: str
    model_class: str
    severity: str
    match: MatchCriteria
    credentials: list[Credential]
    auth: AuthCheck
    description: str = ""


def _build_match(raw: dict) -> MatchCriteria:
    raw = raw or {}
    return MatchCriteria(
        path=raw.get("path", "/"),
        http_title=raw.get("http_title"),
        body_contains=raw.get("body_contains"),
        header_contains=dict(raw.get("header_contains") or {}),
        status_code=raw.get("status_code"),
    )


def _build_auth(raw: dict) -> AuthCheck:
    raw = raw or {}
    success = raw.get("success_status", [200])
    if isinstance(success, int):
        success = [success]
    return AuthCheck(
        type=raw.get("type", "basic"),
        path=raw.get("path", "/"),
        method=raw.get("method", "POST"),
        username_field=raw.get("username_field", "username"),
        password_field=raw.get("password_field", "password"),
        success_status=tuple(success),
        failure_body_contains=raw.get("failure_body_contains"),
        extra_fields=dict(raw.get("extra_fields") or {}),
    )


def _build_credentials(raw_list: list) -> list[Credential]:
    creds: list[Credential] = []
    for entry in raw_list or []:
        creds.append(
            Credential(
                username=str(entry.get("username", "")),
                password=str(entry.get("password", "")),
            )
        )
    return creds


def load_fingerprints_from_dict(data: dict) -> list[Fingerprint]:
    """Build Fingerprint objects from an already-parsed YAML mapping."""
    fingerprints: list[Fingerprint] = []
    for raw in data.get("fingerprints", []):
        fingerprints.append(
            Fingerprint(
                id=raw["id"],
                vendor=raw.get("vendor", ""),
                model_class=raw.get("model_class", ""),
                severity=raw.get("severity", "medium"),
                match=_build_match(raw.get("match", {})),
                credentials=_build_credentials(raw.get("default_credentials", [])),
                auth=_build_auth(raw.get("auth", {})),
                description=raw.get("description", ""),
            )
        )
    return fingerprints


def load_fingerprint_set(name: str, *, directory: Path | None = None) -> list[Fingerprint]:
    """Load a named fingerprint set (e.g. ``"default"``) from a YAML file.

    Raises FileNotFoundError if the set does not exist.
    """
    directory = directory or FINGERPRINTS_DIR
    path = directory / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"fingerprint set not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    return load_fingerprints_from_dict(data)
