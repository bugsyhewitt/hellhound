# hellhound — Post-v0.1 Improvement Directions

Researched: 2026-05-26. Rankings based on threat landscape, user workflow
value, and implementation scope. The Team Lead assigns one item per Phase 2
lap; Workers implement exactly one improvement per lap.

---

## Ranked improvement list

### 1. Expand the fingerprint database — 10+ high-value new entries (PRIORITY) — ✅ IMPLEMENTED (Phase 2, Rotation 2)

**Tranche 5 update (Rotation 16):** Added 8 enterprise edge-appliance / server
device classes from the 2023-2025 KEV / mass-exploitation lists (database now
**48 entries**): Barracuda Email Security Gateway (CVE-2023-2868), Cisco IOS XE
web UI (CVE-2023-20198 / CVE-2023-20273), Progress MOVEit Transfer
(CVE-2023-34362), Progress Telerik (CVE-2024-4358), Atlassian Confluence
(CVE-2023-22515), Ivanti Connect Secure (CVE-2023-46805 / CVE-2024-21887),
Fortinet FortiGate (CVE-2024-21762), and SonicWall Secure Mobile Access
(CVE-2024-38475). Each has a mock-transport unit test in
`tests/test_fingerprints_phase2_tranche5.py` proving fingerprint match and
default-credential authentication, plus a matched-but-rotated guard test. No
engine changes.

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

### 9. Plugin / external fingerprint directory support (`--fingerprint-dir`) — ✅ IMPLEMENTED (Phase 2, Rotation 10)

**Status:** Done. Added `--fingerprint-dir PATH` to the CLI. New
`load_fingerprint_set_with_dir(name, fingerprint_dir=...)` in
`hellhound/fingerprint.py` always loads the bundled set as the base, then merges
a user `<set>.yaml` on top via a new `merge_fingerprints(bundled, overrides)`
helper: custom entries override bundled ones by `id` in place, new ids are
appended, bundled-only entries are preserved (bundled order kept). A missing
directory or a directory without the named `<set>.yaml` raises FileNotFoundError,
which `main()` reports as a clean exit-2 error. 12 unit tests in
`tests/test_fingerprint_dir.py` (merge semantics, loader behaviour, CLI parsing,
error path); README documents the flag with a custom-directory example. No engine
changes.

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

### 10. Async progress reporting (`--progress` flag / `--quiet` flag) — ✅ IMPLEMENTED (Phase 2, Rotation 11)

**Status:** Done. Added `--progress` and `--quiet` (mutually exclusive) flags to
the CLI. `Scanner.scan` gained an optional `progress_callback` that fires once
per completed host with a new `ScanProgress` snapshot (`hosts_done`,
`hosts_total` after exclusions, running `findings_with_default_creds`), keeping
the engine decoupled from any output concern. `cli.resolve_progress_enabled`
decides emission — `--quiet` wins, `--progress` forces on, otherwise it
auto-enables only when stderr is a TTY — and `cli.make_progress_callback` writes
a single carriage-return-rewritten status line to stderr (terminated on the
final host) so stdout stays a clean JSON/CSV/SARIF stream. 13 unit tests in
`tests/test_progress.py` (per-host callback firing, flagged-count semantics,
exclusion-aware totals, enablement decision matrix, line rendering, CLI parsing
and mutual exclusion, and end-to-end stderr capture for both `--progress` and
`--quiet`) using httpx.MockTransport — no network, no Docker. README documents
the flags and adds a Progress output section.

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

### 11. `--list-fingerprints` inventory mode — ✅ IMPLEMENTED (Phase 2, Rotation 12)

**Status:** Done. Items 1–10 above were all shipped (the status notes for items
2–6 were stale; their code, flags, and tests are present), so the original
ranked roadmap was exhausted. This rotation added the highest-value remaining
in-scope gap: an inventory/inspection mode. `--list-fingerprints` prints the
loaded fingerprint database (after any `--fingerprint-dir` merge) and exits
without scanning — no `--target` required. `--target` is now conditionally
required (validated in `main()`). A new
`format_fingerprint_list(fingerprints, fmt)` renders the set in `text`, `json`,
or `csv` (`sarif` falls back to `json`), each entry showing id, vendor,
model_class, severity, auth type/path, default credentials (blank passwords stay
visible), and CVEs. It honours `--output-file`. 15 unit tests in
`tests/test_list_fingerprints.py` (parser surface, all three formats, sarif
fallback, the no-network short-circuit asserting the scanner is never invoked,
the conditional `--target` validation, the output-file path and its error case,
and the custom-directory merge view). README documents the flag in the options
table and a new "Listing the fingerprint database" usage section. No engine
changes.

**Why this gap:** hellhound carries 24+ fingerprints and supports private custom
sets via `--fingerprint-dir`. Operators had no way to see what coverage they had
without reading YAML or running a live scan. Inventory mode answers "what can
this detect?" and "did my custom set merge?" offline, composing with the
existing format/output machinery. It is strictly detection-only and reads no
network, fully within the v0.1 contract and the out-of-scope guardrails.

---

### 12. `--exit-code N` findings-based exit status — ✅ IMPLEMENTED (Phase 2, Rotation 13)

**Status:** Done. Added `--exit-code N` (default `0`) to the CLI. A new pure
helper `cli.resolve_exit_code(findings, exit_code_when_found)` returns
`exit_code_when_found` when any finding has `default_creds is True` and the
operator opted in with a non-zero value; otherwise `0`. Wired into both scan
return paths in `main()` (stdout and `--output-file`), leaving inventory mode and
the exit-2 error paths untouched. The signal is the confirmed-exposure set and is
deliberately independent of `--only-vulnerable` (which only filters displayed
findings), so the exit code is stable across output modes. Default `0` preserves
the original always-exit-0 contract. 16 unit tests in `tests/test_exit_code.py`
(parser surface incl. non-int rejection, the resolve helper across empty/rotated/
flagged/mixed inputs and custom non-zero codes, end-to-end exit on exposure vs
no-exposure, default back-compat, output-file path, `--only-vulnerable`
independence, exit-2 input errors unaffected, and `--list-fingerprints` never
tripping it). README gains an "Exit codes and CI/CD gating" section plus an
options-table row. No engine changes.

**Why this gap:** With items 1–11 shipped the ranked roadmap was exhausted. The
highest-value remaining in-scope gap was the missing exit-status contract: every
mature scanner (trivy, grype, …) lets you fail a pipeline on findings, but
hellhound always exited 0, so it could not gate CI/CD or a shell script without
parsing its own JSON. This is the standard, expected scanner behaviour and is
strictly a reporting concern — detection-only, no new network behaviour, fully
within the v0.1 contract and the out-of-scope guardrails.

---

### 13. Fingerprint tranche 12 — 8 KEV edge/VPN/remote-support classes (96 → 104) — ✅ IMPLEMENTED (Phase 2, Rotation 25)

**Status:** Done. Item 1 (fingerprint-database expansion) remains the standing
top priority, so this rotation extended it with an eighth tranche-style batch of
8 CISA-KEV device classes, taking the bundled `default.yaml` from 96 to 104
entries: Ivanti Cloud Services Appliance (CVE-2024-8190 / CVE-2024-8963), Versa
Director (CVE-2024-39717, "VersaMem"), Trimble Cityworks (CVE-2025-0994),
SimpleHelp remote-support server (CVE-2024-57727), Mitel MiCollab
(CVE-2024-41713), BeyondTrust Privileged Remote Access (CVE-2024-12356), Cisco
ASA / FTD WebVPN (CVE-2024-20353 / CVE-2024-20359, "ArcaneDoor"), and Juniper
Junos J-Web (CVE-2023-36844). Each entry carries its `cve` list and a
form-auth check. 9 mock-transport unit tests in
`tests/test_fingerprints_phase2_tranche12.py` (one per entry proving fingerprint
match + default-credential authentication, plus a matched-but-rotated guard
using the Ivanti CSA entry) prove detection with no network and no Docker. No
engine changes. README "Fingerprint format" coverage paragraph, the count, and
the `--list-fingerprints` example output updated to 104.

**Considered but not chosen this rotation:** a `--profile` /
`custom-fingerprint-set` alias flag. On inspection the requested capability is
already served by the shipped `--fingerprint-set` (selects a named bundled set)
and `--fingerprint-dir` (merges a user `<set>.yaml` over the bundled base), so a
`--profile` flag would be a redundant alias rather than new value. The
fingerprint-database expansion (roadmap item 1, the standing top priority)
delivered real new coverage instead.

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
