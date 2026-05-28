# hellhound — Post-v0.1 Improvement Directions

Researched: 2026-05-26. Rankings based on threat landscape, user workflow
value, and implementation scope. The Team Lead assigns one item per Phase 2
lap; Workers implement exactly one improvement per lap.

---

## Ranked improvement list

### 1. Expand the fingerprint database — 10+ high-value new entries (PRIORITY) — ✅ IMPLEMENTED (Phase 2, Rotation 2)

**Status:** Done. All 12 new fingerprints below were added to
`hellhound/fingerprints/default.yaml` (database now 24 entries), each with a
mock-transport unit test in `tests/test_fingerprints_phase2.py` proving
fingerprint match and default-credential detection. No engine changes.

**Why first:** The fingerprint database is the core product. v0.1 shipped 12
entries covering the classic Mirai-era targets (Hikvision, Dahua, MikroTik,
etc.). The 2025-2026 threat landscape reveals several under-covered
high-prevalence device classes that Mirai variants and newer botnets
(Nexcorium, Aisuru) actively target.

Confirmed new fingerprints to add, with verified default credentials:

| Device class | Vendor | Default creds | Auth type | Notes |
|---|---|---|---|---|
| IP camera | Reolink | admin / (blank) | form | HTTP on port 80; body contains `reolink` or `ReoLink` |
| IP phone / AP | Grandstream GXP/GWN | admin / admin | form/basic | Path `/cgi-bin/dologin.cgi`; body or title contains "Grandstream" |
| Enterprise AP | HPE Aruba Instant On | admin / default123 | basic | CVE-2025-37103; affects APs running firmware ≤ 3.2.0.1; path `/api/v1/login` |
| SOHO router | Tenda | admin / admin | form | Title "Tenda"; common across A, AC, F series |
| NVR/DVR | Amcrest | admin / admin | basic | Title "Amcrest" or "AMCREST" |
| IP camera | Vivotek | root / (blank) | basic | Title "VIVOTEK" |
| IP camera | Axis (2nd gen) | root / root | basic | Newer models before enforcement; supplemental to existing axis-camera entry |
| SOHO router | Linksys WRT | admin / admin | basic | WWW-Authenticate: "Linksys" |
| SOHO router | ASUS router | admin / admin | form | Title "ASUS"; path `/login.cgi` |
| Industrial serial server | Moxa NPort | admin / (blank) | basic | Title "Moxa NPort"; path `/cgi-bin/mainpage.cgi` |
| Smart DVR | GeoVision | admin / admin | basic | Title "GeoVision"; actively targeted by Mirai via CVE-2024-6047/CVE-2024-11120 |
| SOHO router | NETGEAR Orbi | admin / password | basic | Supplement to existing netgear-router for Orbi mesh series |

**Implementation scope:** Add a new YAML block per entry, one mock-transport
unit test per new entry proving fingerprint match and default-cred detection.
No engine changes required.

---

### 2. `--output-file` flag + CSV output format

**Why second:** JSON stdout is fine for piping, but red teamers and sysadmins
working through a CIDR sweep want a persistent artefact they can open in a
spreadsheet or import into a SIEM. The lack of a file output option is the
most visible usability gap after the fingerprint count.

**Implementation scope:**
- Add `--output-file PATH` to the CLI (defaults to stdout as today).
- Add `--format csv` as a third option alongside `json` and `text`. CSV
  columns: `host,port,scheme,vendor,model_class,severity,fingerprint_id,default_creds,username,password,evidence`.
- Update `format_output` to accept a `stream` parameter; `main()` opens the
  file and passes it through.
- Tests: CLI unit tests covering `--format csv --output-file` path.
- README: update the Options table and add a CSV output example.

---

### 3. `--exclude` / `--exclude-file` flag for IP/CIDR exclusion lists

**Why third:** In authorised lab or enterprise scans, operators need to exclude
known-good management hosts, out-of-scope subnets, or recently patched devices
without manually editing targets. Without exclusion support, hellhound is
awkward to run in environments with mixed in-scope and out-of-scope ranges.

**Implementation scope:**
- Add `--exclude CIDR|IP` (repeatable) and `--exclude-file PATH` (one entry
  per line, `#` comments) flags to the CLI.
- Implement `Scanner.expand_targets` exclusion logic: after expansion, filter
  out any host matching an excluded CIDR or exact IP.
- Tests: unit tests for exclusion of single IPs and CIDR ranges within a
  larger CIDR.
- README: add an Exclusions section with examples.

---

### 4. Digest / summary mode with `--only-vulnerable` flag

**Why fourth:** In large CIDR sweeps, most hosts are either unreachable or
produce no fingerprint match. The full JSON findings list is verbose when the
operator only cares about confirmed default-credential exposures. A flag that
suppresses no-match and matched-but-rotated findings reduces noise.

**Implementation scope:**
- Add `--only-vulnerable` flag to CLI (boolean).
- In `format_output`, when the flag is set, filter `findings` to only those
  where `default_creds is True` before formatting.
- Update summary counts to show filtered vs total (e.g.,
  `"devices_scanned": 254, "devices_matched": 6, "devices_with_default_creds": 2`).
- Tests: CLI and formatter unit tests for the flag.
- README: add a note to the Output section.

---

### 5. Per-finding CVE cross-reference in the fingerprint schema

**Why fifth:** Operators need to communicate risk to asset owners. Linking a
finding to a CVE (e.g., HPE Aruba CVE-2025-37103, GeoVision CVE-2024-6047)
dramatically improves the actionability of a hellhound report. This is a
schema extension with no engine change.

**Implementation scope:**
- Add optional `cve` list field to the YAML fingerprint schema (list of
  strings, e.g. `["CVE-2025-37103"]`).
- Extend `Fingerprint` dataclass with `cve: list[str]` (default `[]`).
- Extend `Finding.to_dict()` and text output to include CVE references when
  present.
- Backfill known CVEs into the default.yaml entries (Aruba, GeoVision, AVTECH
  CVE-2024-7921, etc.).
- Tests: schema loading test for CVE field; Finding serialisation test.
- README: add CVE field documentation to the Fingerprint format section.

---

### 6. Retry / resilience: configurable per-host retry with exponential backoff

**Why sixth:** IoT devices on flaky consumer broadband or overloaded embedded
webservers frequently drop the first connection, producing false negatives. A
single silent retry with a short backoff recovers many of these without
materially slowing scans.

**Implementation scope:**
- Add `--retries N` (default `1`) to the CLI.
- In `Scanner._safe_get` and `Scanner._try_auth`, wrap the request in a
  retry loop with 0.5s × attempt backoff, catching `httpx.TransportError`.
- Tests: MockTransport that fails once then succeeds; assert the finding is
  still produced.
- README: add `--retries` to the options table.

---

### 7. Digest report: machine-readable SARIF 2.1.0 output format — ✅ IMPLEMENTED (Phase 2, Rotation 8)

**Status:** Done. Added `--format sarif`, a `format_sarif(findings)` builder in
`hellhound/cli.py` producing a valid SARIF 2.1.0 document (one `result` per
confirmed default-credential finding, severity → SARIF `level` mapping, host/port
as a location URI, CVEs as result tags/properties, deduplicated rules per
fingerprint), with 12 unit tests in `tests/test_sarif.py` and README docs
including a GitHub code-scanning upload example. No engine changes.

**Why seventh:** Security teams integrating hellhound into CI/CD pipelines or
GitHub Advanced Security expect SARIF output for code-scanning upload. SARIF
2.1.0 is the OASIS-standard format accepted by GitHub, GitLab, Harness, and
most enterprise scanners.

**Implementation scope:**
- Add `--format sarif` option.
- Implement a `format_sarif(findings)` function that produces a minimal valid
  SARIF 2.1.0 document: `runs[0].tool.driver.name = "hellhound"`, one `result`
  per finding with `default_creds: true`, severity mapped to SARIF `level`
  (critical/high → `error`, medium → `warning`, low → `note`), and a `locations`
  array encoding the host/port as a URI.
- Tests: SARIF output structure validation.
- README: add SARIF to the Output section with a GitHub upload example.

---

### 8. Digest report: `--rate-limit` flag (requests/second cap) — ✅ IMPLEMENTED (Phase 2, Rotation 9)

**Status:** Done. Added `--rate-limit N` to the CLI (requests/second, `0` =
unlimited, default `0`) wired into `Scanner(rate_limit=...)`. The `Scanner`
seats a leaky-bucket throttle (`_throttle()`) above the concurrency semaphore in
the single request chokepoint `_with_retries`, so every outbound request —
landing-page fetch and auth check, including retries — is paced at least
`1 / rate_limit` seconds apart across the whole scan. Slot reservation is
serialised by an `asyncio.Lock` while the sleep itself happens outside the lock,
so the cap holds without serialising waits. 7 unit tests in
`tests/test_rate_limit.py` (deterministic via a fake monotonic clock + fake
`asyncio.sleep`) cover min-interval config, negative-value clamping, request
pacing, the no-throttle no-op path, no-overpacing once the clock advances, and
CLI parsing. README options table updated with the embedded-device note.

**Why eighth:** Default concurrency of 50 with no rate cap can overwhelm small
embedded devices, trigger firmware-level watchdog reboots on some cameras, or
trip IDS rules in monitored environments. A requests-per-second cap gives
operators control without requiring them to reason about concurrency.

**Implementation scope:**
- Add `--rate-limit N` (requests per second, `0` = unlimited, default `0`).
- Implement a token-bucket throttle in `Scanner` that seats above the
  semaphore: a `asyncio.Queue`-based or `asyncio.sleep`-based leaky bucket.
- Tests: timing test with a tight rate limit asserting request pacing.
- README: add `--rate-limit` to the options table with a note about embedded
  device sensitivity.

---

### 9. Plugin / external fingerprint directory support (`--fingerprint-dir`)

**Why ninth:** Power users want to maintain a private fingerprint set for
proprietary or unreleased devices alongside the bundled `default.yaml` without
patching hellhound itself. Allowing a user-specified directory enables both
private sets and easy community contribution.

**Implementation scope:**
- Add `--fingerprint-dir PATH` flag. When set, `load_fingerprint_set` looks
  there first, falling back to the bundled `fingerprints/` directory.
- Merge semantics: fingerprints from the user directory override bundled ones
  by `id`; the rest are appended.
- Tests: temp directory with a custom YAML; assert custom fingerprint is
  picked up and bundled ones still present.
- README: document `--fingerprint-dir` with an example of a custom set.

---

### 10. Async progress reporting (`--progress` flag / `--quiet` flag)

**Why tenth:** When scanning a /16 or /24 range, hellhound prints nothing until
all results are ready. Operators have no feedback that the scan is running.
A progress line to stderr (hosts scanned / total, findings so far) makes long
scans manageable without polluting stdout JSON.

**Implementation scope:**
- Add `--progress` flag (enabled by default if stdout is a TTY, disabled
  otherwise — detect with `sys.stdout.isatty()`).
- Add `--quiet` flag to suppress all stderr output including progress.
- In `Scanner.scan`, emit a progress line to `sys.stderr` after each host
  batch completes (every 10 hosts, or every completed `_scan_host` call).
- Tests: capture stderr during a scan and assert progress lines emitted when
  flag is set; assert no stderr in quiet mode.
- README: add a note on progress output in the Usage section.

---

## Out-of-scope (not in any Phase 2 lap)

These directions are explicitly out of scope for hellhound and must not be
implemented by any Worker:

- Telnet / SSH scanning or brute-forcing
- Any active exploitation or post-auth action
- Shodan / Censys API integration (Shodan as a *source* of IPs is operator
  responsibility)
- Web UI or persistent daemon mode
- Firmware extraction or analysis
- Non-default credential wordlists / brute force
- Agent / scheduled mode
