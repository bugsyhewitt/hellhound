# Changelog

All notable changes to hellhound are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-06-20

### Added
- 200 KEV-targeted device-class fingerprint entries in `hellhound/fingerprints/default.yaml`
  (PRs #1–#36 cumulative: 8-entry tranches adding Hikvision, Dahua, TP-Link, D-Link,
  Trendnet, Foscam, Vivotek, Avtech, GeoVision, HIKVision NVR, Dahua NVR, Xiongmai,
  TBK, Sony, Panasonic, Axis, Bosch, Arecont, ACTi, Zavio, Topview, Apexis, Agasio,
  Wansview, AirLive, Sywology, D-Link DWR, TP-Link Archer, ASUS RT, Netgear R7000,
  Linksys EA, Huawei HG, ZTE, MikroTik, Ubiquiti, Sonicwall, Fortinet, Palo Alto,
  Barracuda, Checkpoint, Juniper SRX, Cisco ASA, Meraki MX, Aruba, Ruckus, Aerohive,
  Aruba Instant, Ubiquiti UniFi, Cambium, Mimosa, Radwin, Exalt, Redline, Aviat,
  Ceragon, NEC iPasolink, SIAE, Ericsson MINI-LINK, Huawei RTN, ZTE iSeries,
  Ceragon Evolution, Aviat WTM, NEC iPasolink 1000, Huawei OptiX RTN 905, ZTE iSeries
  V3, Ericsson MINI-LINK 6352, plus tranche 24 adding Icinga2 Web, Graylog, Checkmk,
  Pandora FMS, LibreNMS, OpenNMS Horizon, OTRS, and ManageEngine OpManager with CISA
  KEV or mass-exploitation records from 2022–2024; total 200 entries as of
  PR #36 MERGED 2026-06-05T15:03:56Z).
- CLI flags: `--target` (single host or CIDR), `--ports`, `--fingerprint-set`,
  `--format` (text/json/csv/sarif), `--list-fingerprints`, `--validate`,
  `--output-file`, `--timeout`, `--concurrency`, `--retries`, `--rate-limit`,
  `--exclude`, `--only-vulnerable`, `--exit-code`, `--progress`/`--quiet`,
  `--fingerprint-dir`, `--version`, `--help` (added across PRs #1–#37).
- SARIF v2.1.0 output format with CVE cross-references (PR #17 + extensions).
- Async progress reporting (`--progress`/`--quiet` — PR #9, POST_V01 Rank 10).
- `hosts_scanned` sweep denominator in scan summary (PR #19).
- V01_CRITERIA.md formalizing the 6-criterion v0.1 acceptance bar (PR #37 MERGED 2026-06-18T16:35:02Z).
- v1.0 release ship-gate: `tests/test_wheel_ship_gate.py` with 5 baseline tests
  (wheel build, fresh-venv install + version, fresh-venv import + version,
  fresh-venv `--list-fingerprints` smoke, fresh-venv `--validate` clean) + 1
  CHANGELOG pin test = 6 `@pytest.mark.ship_gate` tests; `ship_gate` marker
  registered in `pyproject.toml [tool.pytest.ini_options].markers = [...]`.

### Changed
- Version bump: `0.1.0` → `1.0.0` (pyproject.toml:7, hellhound/__init__.py:9).
- The 200 fingerprint entries are the production-ready v1.0 surface;
  no functional change to the detection or credential-check logic.

### Fixed
- (None — all v0.1.x work was feature-adding, not bug-fixing.)

### Security
- hellhound is **detection-only**: it reports devices that still accept
  factory-default credentials, it does not exploit them. All credential
  checks are passive (HTTP basic / form auth against the device's own
  web surface) and produce no side effects on the target.
- The 200 KEV-targeted device classes are sourced from CISA's Known
  Exploited Vulnerabilities catalog and from public mass-exploitation
  records (Mirai botnet, Mēris botnet, etc.) covering 2016–2024.

[1.0.0]: https://github.com/bugsyhewitt/hellhound/releases/tag/v1.0.0
