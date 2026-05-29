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
VALID_AUTH_TYPES = frozenset({"basic", "form"})


class FingerprintValidationError(ValueError):
    """A fingerprint set failed structural validation.

    Raised by :func:`validate_fingerprints` (and, by extension, the validating
    load path) when one or more entries are malformed. The message enumerates
    every problem found — not just the first — so an author fixing a custom set
    sees all the issues at once. The full list is also available on the
    ``errors`` attribute.
    """

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        count = len(self.errors)
        noun = "error" if count == 1 else "errors"
        joined = "\n".join(f"  - {e}" for e in self.errors)
        super().__init__(f"{count} fingerprint {noun}:\n{joined}")


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
    cve: tuple[str, ...] = ()


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


def _build_cve(raw: object) -> tuple[str, ...]:
    """Normalise a fingerprint's optional ``cve`` field into a tuple of strings.

    Accepts a list of strings, a single string, or absence (``None``). Blank
    entries are dropped so a stray empty string never appears in output.
    """
    if not raw:
        return ()
    if isinstance(raw, str):
        raw = [raw]
    return tuple(str(c).strip() for c in raw if str(c).strip())


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
                cve=_build_cve(raw.get("cve")),
            )
        )
    return fingerprints


def validate_fingerprints(fingerprints: list[Fingerprint]) -> list[str]:
    """Check a loaded fingerprint set for structural integrity.

    The fingerprint database is hellhound's core product, and it has grown to
    dozens of entries maintained across many contributions. A typo or copy-paste
    slip silently degrades the tool: an invalid severity corrupts the SARIF level
    mapping, a duplicate id breaks ``--fingerprint-dir`` merging and SARIF rule
    deduplication, a fingerprint with no positive match condition can never fire,
    and a fingerprint with no default credentials has nothing to check. None of
    these raise on their own — they just quietly produce wrong results.

    This returns a list of human-readable error strings (empty when the set is
    valid), checking each entry for:

    - **duplicate id** — every fingerprint id must be unique within a set;
    - **invalid severity** — must be one of :data:`VALID_SEVERITIES`;
    - **invalid auth type** — must be one of :data:`VALID_AUTH_TYPES`;
    - **non-meaningful match** — at least one of ``http_title`` / ``body_contains``
      / ``header_contains`` must be set, or the entry can never match;
    - **no default credentials** — a fingerprint with nothing to test is useless.

    All problems are collected, not just the first, so an author can fix them in
    one pass.
    """
    errors: list[str] = []
    seen: dict[str, int] = {}

    for idx, fp in enumerate(fingerprints):
        # A blank id makes every other error message ambiguous, so flag it first
        # but still report the rest using a positional label.
        label = fp.id if fp.id else f"<entry {idx} with no id>"
        if not fp.id:
            errors.append(f"entry {idx}: missing 'id'")

        if fp.id:
            seen[fp.id] = seen.get(fp.id, 0) + 1

        if fp.severity not in VALID_SEVERITIES:
            errors.append(
                f"{label}: invalid severity {fp.severity!r} "
                f"(expected one of {sorted(VALID_SEVERITIES)})"
            )

        if fp.auth.type not in VALID_AUTH_TYPES:
            errors.append(
                f"{label}: invalid auth type {fp.auth.type!r} "
                f"(expected one of {sorted(VALID_AUTH_TYPES)})"
            )

        if not fp.match.is_meaningful():
            errors.append(
                f"{label}: match has no positive condition "
                "(set at least one of http_title / body_contains / header_contains) "
                "— it can never match a device"
            )

        if not fp.credentials:
            errors.append(
                f"{label}: no default_credentials — nothing to check"
            )

    for fp_id, count in seen.items():
        if count > 1:
            errors.append(f"duplicate id {fp_id!r} appears {count} times")

    return errors


def load_fingerprint_set(
    name: str, *, directory: Path | None = None, validate: bool = False
) -> list[Fingerprint]:
    """Load a named fingerprint set (e.g. ``"default"``) from a YAML file.

    Raises FileNotFoundError if the set does not exist. When *validate* is True,
    the loaded set is checked with :func:`validate_fingerprints` and a
    :class:`FingerprintValidationError` is raised if any entry is malformed.
    """
    directory = directory or FINGERPRINTS_DIR
    path = directory / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"fingerprint set not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    fingerprints = load_fingerprints_from_dict(data)
    if validate:
        errors = validate_fingerprints(fingerprints)
        if errors:
            raise FingerprintValidationError(errors)
    return fingerprints


def merge_fingerprints(
    bundled: list[Fingerprint],
    overrides: list[Fingerprint],
) -> list[Fingerprint]:
    """Merge a user *overrides* set on top of the *bundled* set, keyed by id.

    Merge semantics (per POST_V01 item 9):

    - A fingerprint in *overrides* whose ``id`` matches a bundled entry
      *replaces* that bundled entry in place (so an operator can correct or
      retune a shipped fingerprint without forking the database).
    - A fingerprint in *overrides* with an ``id`` not present in the bundled
      set is *appended* after the bundled entries.
    - Bundled-only entries are preserved.

    Bundled ordering is preserved; new override entries follow in the order
    they appear in the user directory.
    """
    by_id: dict[str, Fingerprint] = {fp.id: fp for fp in overrides}
    merged: list[Fingerprint] = []
    seen: set[str] = set()
    for fp in bundled:
        merged.append(by_id.get(fp.id, fp))
        seen.add(fp.id)
    for fp in overrides:
        if fp.id not in seen:
            merged.append(fp)
            seen.add(fp.id)
    return merged


def load_fingerprint_set_with_dir(
    name: str,
    *,
    fingerprint_dir: Path | None = None,
    validate: bool = False,
) -> list[Fingerprint]:
    """Load the bundled *name* set, optionally merged with a user directory.

    The bundled fingerprints under :data:`FINGERPRINTS_DIR` are always loaded
    as the base. When *fingerprint_dir* is provided and contains
    ``{name}.yaml``, that file is loaded and merged on top using
    :func:`merge_fingerprints` (user entries override bundled ones by ``id``;
    the rest are appended). This lets power users maintain a private fingerprint
    set alongside the shipped database without patching hellhound.

    When *validate* is True, the *effective* (post-merge) set is checked with
    :func:`validate_fingerprints`; a :class:`FingerprintValidationError` is
    raised if it is malformed. Validating after the merge is deliberate — it is
    exactly the merged set hellhound will scan with, and the merge is where a
    custom set is most likely to introduce a bad severity or auth type.

    Raises FileNotFoundError if the bundled set does not exist, or if a
    *fingerprint_dir* is given but does not exist / contains no ``{name}.yaml``.
    """
    bundled = load_fingerprint_set(name)
    if fingerprint_dir is None:
        effective = bundled
    else:
        fingerprint_dir = Path(fingerprint_dir)
        if not fingerprint_dir.is_dir():
            raise FileNotFoundError(
                f"fingerprint directory not found: {fingerprint_dir}"
            )
        user_path = fingerprint_dir / f"{name}.yaml"
        if not user_path.is_file():
            raise FileNotFoundError(
                f"no '{name}.yaml' in fingerprint directory: {fingerprint_dir}"
            )
        overrides = load_fingerprint_set(name, directory=fingerprint_dir)
        effective = merge_fingerprints(bundled, overrides)

    if validate:
        errors = validate_fingerprints(effective)
        if errors:
            raise FingerprintValidationError(errors)
    return effective
