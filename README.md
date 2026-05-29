# hellhound

Linux-native IoT default-credential scanner with a maintained device-fingerprint
database. hellhound scans a CIDR range or single host over HTTP/HTTPS, recognises
known IoT device classes from their web surface, and checks whether each matched
device still accepts its **factory-default credentials**.

It is a focused, modern successor to Rapid7's `IoTSeeker` — the Perl tool built
after the 2016 Mirai outage to find IoT devices still running on default logins.
That tool no longer builds on current Linux; hellhound is a Python rewrite of the
same idea with an async HTTP engine and a maintainable YAML fingerprint database.

**hellhound is detection-only.** It reports devices that still accept default
credentials so the owner can rotate them. It does not exploit, brute-force
non-default credentials, or take any action beyond a single authentication check.

---

## Ethical use notice

**This tool authenticates against devices using known default credentials. That
can be aggressive and, used against systems you do not own or have explicit
written permission to test, is very likely illegal** (e.g. computer-misuse and
unauthorised-access statutes in many jurisdictions).

Legitimate-use boundaries:

- **Only scan networks and devices you own or are explicitly authorised to test
  in writing** (your own lab, your employer's assets under an engagement, or a
  bug-bounty program whose scope explicitly permits credential checks).
- **Respect bug-bounty scope.** Many IoT programs (Ring, Wyze, smart-home
  vendors) allow security research only within published rules — read them first.
- **Do not use hellhound to gain or maintain access.** It is a detection tool.
  Finding a default-credential exposure is the end of hellhound's job; report it.
- **Rate and target responsibly.** Scanning broad public ranges without
  authorisation is abuse, regardless of intent.

You are responsible for how you use this tool. When in doubt, don't scan.

---

## Install

Requires Python 3.13+.

```bash
git clone https://github.com/bugsyhewitt/hellhound
cd hellhound
pip install -e .
```

Verify:

```bash
hellhound --help
```

---

## Usage

Scan a single host on the default ports and print JSON findings:

```bash
hellhound --target 192.0.2.10
```

Scan a CIDR range on specific ports, using the default fingerprint set, with
human-readable output:

```bash
hellhound --target 192.0.2.0/24 --ports 80,443,8080 --fingerprint-set default --format text
```

Key options:

| Flag | Description | Default |
|---|---|---|
| `--target`, `-t` | CIDR range or single IP/host. Repeat for multiple targets. | *(required unless `--list-fingerprints`)* |
| `--ports`, `-p` | Comma-separated ports to probe. | `80,443,8080,8443` |
| `--fingerprint-set`, `-f` | Name of the fingerprint set under `hellhound/fingerprints/`. | `default` |
| `--fingerprint-dir` | Directory holding a custom `<set>.yaml`. Custom entries override bundled ones by `id`; the rest are appended. | *(none)* |
| `--list-fingerprints` | Inventory mode: print the loaded fingerprint database (after any `--fingerprint-dir` merge) and exit without scanning. Honours `--format` and `--output-file`; no target required. | *(off)* |
| `--validate` | Validate the loaded fingerprint database (after any `--fingerprint-dir` merge) for structural integrity and exit without scanning. Exits `0` if valid, `2` (listing every problem) if not. No target required. | *(off)* |
| `--format` | `json`, `text`, `csv`, or `sarif`. | `json` |
| `--output-file`, `-o` | Write output to this path instead of stdout. | *(stdout)* |
| `--timeout` | Per-request timeout (seconds). | `5.0` |
| `--concurrency` | Max concurrent requests. | `50` |
| `--rate-limit` | Cap outbound requests per second across the whole scan (`0` = unlimited). Seats above `--concurrency` so high concurrency never exceeds the rate. | `0` |
| `--retries` | Total attempts per request before giving up. `>1` retries transient connection failures with exponential backoff. | `1` |
| `--exclude`, `-e` | Exclude a CIDR or IP from scanning. Repeatable. | *(none)* |
| `--exclude-file` | Path to a file of CIDR/IP exclusions (one per line, `#` comments). | *(none)* |
| `--only-vulnerable` | Digest mode: report only findings with confirmed default credentials. Summary counts stay full. | *(off)* |
| `--exit-code` | Exit with this code when a confirmed default-credential exposure is found (`0` = always exit 0 on a successful scan). Use a non-zero value to fail CI/CD or scripts. | `0` |
| `--progress` | Emit a live progress line to stderr (hosts scanned / total, findings so far). Auto-on when stderr is a TTY. | *(auto)* |
| `--quiet`, `-q` | Suppress all stderr output, including the progress line. Mutually exclusive with `--progress`. | *(off)* |

### Progress output

A scan over a large CIDR range (a `/24` or `/16`) prints nothing on stdout until
every host has been probed. To show that the scan is alive, hellhound writes a
single, self-rewriting progress line to **stderr** as each host completes:

```
hellhound: 142/254 hosts scanned, 3 with default creds
```

The line auto-enables when stderr is an interactive terminal and stays silent
when output is piped or redirected, so machine consumers never see it. Force it
on (even when redirected) with `--progress`, or turn off all stderr chatter with
`--quiet`. Because progress goes to stderr, stdout remains a clean JSON / CSV /
SARIF stream you can pipe or save:

```bash
# live progress in the terminal, clean JSON saved to disk
hellhound --target 10.0.0.0/24 --progress --output-file findings.json

# fully silent on stderr (e.g. inside a cron job)
hellhound --target 10.0.0.0/24 --quiet > findings.json
```

### Listing the fingerprint database

Before a scan, you often want to know *what hellhound can detect* — which device
classes, vendors, severities and CVEs the loaded set covers. `--list-fingerprints`
prints the database and exits without touching the network. No `--target` is
required.

```bash
# human-readable inventory
hellhound --list-fingerprints --format text
```

```
hellhound: 96 fingerprint(s) loaded
[CRITICAL] hikvision-dvr: Hikvision (DVR / NVR / IP Camera) auth=basic
  default creds: admin:12345
[CRITICAL] dahua-dvr: Dahua (DVR / NVR / IP Camera) auth=form
  default creds: admin:admin
...
```

It honours `--format` (`json`, `text`, `csv`; `sarif` falls back to `json`) and
`--output-file`, so you can pipe the inventory into a spreadsheet or a coverage
report:

```bash
# machine-readable coverage audit
hellhound --list-fingerprints --format json

# CSV inventory saved to disk
hellhound --list-fingerprints --format csv --output-file coverage.csv
```

Because it loads through the same path as a scan, it reflects any
`--fingerprint-dir` merge — a quick way to confirm a custom set merged as
expected before running a sweep:

```bash
hellhound --list-fingerprints --fingerprint-dir ~/fp --format text
```

### Validating the fingerprint database

The fingerprint database is hellhound's core asset, and a private set loaded
with `--fingerprint-dir` is easy to get subtly wrong — a mistyped severity, an
unsupported auth type, a duplicate id, a `match` block with no positive
condition (so it can never fire), or an entry with no default credentials. None
of these crash the scanner; they just silently degrade results (a bad severity
quietly mismaps the SARIF level, a duplicate id breaks the merge and SARIF rule
grouping, a dead fingerprint never matches). `--validate` checks the **effective
set hellhound would actually scan with** — the bundled database merged with any
`--fingerprint-dir` overrides — and exits without touching the network:

```bash
# sanity-check the bundled database
hellhound --validate

# gate a private set before a sweep (and in CI)
hellhound --validate --fingerprint-dir ~/fp
```

It reports **every** problem it finds, not just the first, so you can fix a
custom set in one pass:

```
error: fingerprint set 'default' failed validation (3 problem(s)):
  - acme-cam: invalid severity 'criticl' (expected one of ['critical', 'high', 'low', 'medium'])
  - acme-cam: invalid auth type 'telnet' (expected one of ['basic', 'form'])
  - widget-nvr: match has no positive condition (set at least one of http_title / body_contains / header_contains) — it can never match a device
```

A valid set prints a one-line confirmation and exits `0`; an invalid one prints
the problems to stderr and exits `2`, so it drops cleanly into a CI step that
fails the build on a malformed fingerprint set:

```bash
hellhound --validate --fingerprint-dir ./fingerprints || exit 1
```

The checks are: unique ids, severity in `low`/`medium`/`high`/`critical`, auth
type in `basic`/`form`, at least one positive `match` condition, and at least
one default credential per entry.

### Output

JSON output groups a summary with per-device findings:

```json
{
  "summary": {
    "devices_matched": 1,
    "devices_with_default_creds": 1,
    "only_vulnerable": false,
    "hosts_scanned": 254
  },
  "findings": [
    {
      "host": "192.0.2.10",
      "port": 80,
      "scheme": "http",
      "url": "http://192.0.2.10:80/",
      "fingerprint_id": "hikvision-dvr",
      "vendor": "Hikvision",
      "model_class": "DVR / NVR / IP Camera",
      "severity": "critical",
      "default_creds": true,
      "matched_credential": { "username": "admin", "password": "12345" },
      "cve": [],
      "evidence": "matched Hikvision via title/body; default creds admin:12345 authenticated at /ISAPI/Security/userCheck"
    }
  ]
}
```

A finding with `"default_creds": true` is the actionable result: that device
still accepts the listed default credentials and should be reconfigured.

The `summary` also reports `hosts_scanned` — the number of hosts actually
probed after CIDR expansion and any `--exclude` filtering. This is the sweep
denominator: "matched 1 of 254 scanned" is very different from "matched 1 of 1
scanned", and the count is what lets you reason about coverage when you open a
saved report later. The `--progress` line shows the same total live on stderr,
but that disappears once output is piped to a file, so the count is carried in
the persistent json/text summary too. The text format leads with it:

```text
hellhound: 254 host(s) scanned, 1 device(s) matched, 1 with default creds
```

(The CSV format is one row per finding and carries no summary block, so the
count does not appear there.)

Each finding also carries a `cve` list. When the matched fingerprint is linked
to one or more published CVEs (for example HPE Aruba Instant On
`CVE-2025-37103` or GeoVision `CVE-2024-6047`), they appear here so the finding
can be communicated to the asset owner with an authoritative reference. For
fingerprints with no associated CVE the list is empty.

#### Digest mode (`--only-vulnerable`)

On a large CIDR sweep most hosts are unreachable or match no fingerprint, and
many that do match have already had their default credentials rotated. When you
only care about confirmed exposures, pass `--only-vulnerable` to drop every
no-match and matched-but-rotated finding from the output:

```bash
hellhound --target 192.0.2.0/24 --only-vulnerable
```

The findings list is filtered to entries where `default_creds` is `true`, but
the `summary` still reports the full picture so you don't lose situational
awareness — `devices_matched` is the total that matched a fingerprint,
`devices_with_default_creds` is how many of those were exposed,
`only_vulnerable` records that digest mode was applied, and `hosts_scanned`
keeps the sweep denominator even though the findings list is trimmed:

```json
{
  "summary": {
    "devices_matched": 37,
    "devices_with_default_creds": 4,
    "only_vulnerable": true,
    "hosts_scanned": 65534
  },
  "findings": [
    { "host": "192.0.2.10", "default_creds": true, "vendor": "Hikvision", "...": "..." }
  ]
}
```

Digest mode works with every format (`json`, `text`, `csv`) and composes with
`--output-file`, so you can write a SIEM-ready CSV of only the exposed devices:

```bash
hellhound --target 10.0.0.0/16 --only-vulnerable --format csv --output-file exposed.csv
```

#### SARIF output (`--format sarif`)

For CI/CD pipelines and GitHub code scanning, `--format sarif` emits a SARIF
2.1.0 document — the OASIS-standard format accepted by GitHub Advanced
Security, GitLab, Harness, and most enterprise scanners. SARIF reports
vulnerabilities only: hellhound emits one `result` per device with confirmed
default credentials (matched-but-rotated findings are not exposures and are
omitted), maps each finding's severity onto the SARIF `level` vocabulary
(`critical`/`high` → `error`, `medium` → `warning`, otherwise `note`), encodes
the host/port as a location URI, and carries any associated CVEs as result
tags.

```bash
hellhound --target 192.0.2.0/24 --format sarif --output-file hellhound.sarif
```

Upload the artefact to GitHub code scanning from a workflow step:

```yaml
- name: Upload hellhound SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: hellhound.sarif
```

A SARIF document looks like:

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "hellhound",
          "rules": [
            { "id": "hikvision-dvr", "name": "Hikvision default credentials", "...": "..." }
          ]
        }
      },
      "results": [
        {
          "ruleId": "hikvision-dvr",
          "level": "error",
          "message": { "text": "matched Hikvision via title/body; default creds admin:12345 authenticated" },
          "locations": [
            { "physicalLocation": { "artifactLocation": { "uri": "http://192.0.2.10:80/" } } }
          ]
        }
      ]
    }
  ]
}
```

### Exit codes and CI/CD gating

By default a successful scan always exits `0`, whether or not it found anything —
hellhound's job is to *report*, and the findings are in the output. That makes it
awkward to drop into a pipeline, where you usually want a non-zero status to fail
the build when an exposed device turns up.

`--exit-code N` opts into findings-based exit status: when at least one finding
has confirmed default credentials, hellhound exits with code `N` instead of `0`.
The output is identical; only the process exit status changes.

```bash
# fail the pipeline (exit 1) if any device on the range still has default creds
hellhound --target 10.0.0.0/24 --exit-code 1 --output-file findings.json

# shell gating
if ! hellhound --target 10.0.0.0/24 --exit-code 1 --quiet > findings.json; then
  echo "default-credential exposure found — see findings.json"
fi
```

The signal is the confirmed-exposure set (`default_creds: true`). Matched-but-
rotated devices do not trip it, and it is independent of `--only-vulnerable`
(which only filters *displayed* findings, not the underlying match set), so the
exit code is stable across output modes. Input/usage errors and I/O failures
still exit `2` regardless of `--exit-code`. The standard scanner exit conventions
hold:

| Exit code | Meaning |
|---|---|
| `0` | Scan completed; no exposure found, **or** `--exit-code` left at its `0` default |
| `N` (e.g. `1`) | Scan completed and a confirmed default-credential exposure was found (only when `--exit-code N` is set) |
| `2` | Argument, input, or I/O error (unknown fingerprint set, bad ports, unwritable output file, …) |

### Exclusions

Use `--exclude` and/or `--exclude-file` to skip known-safe or out-of-scope
hosts after target expansion. Exclusions are applied before any scanning takes
place so no network traffic is sent to excluded addresses.

Exclude a single IP or a CIDR range with a repeatable flag:

```bash
hellhound --target 192.0.2.0/24 --exclude 192.0.2.1 --exclude 192.0.2.100/30
```

For larger exclusion lists, put them in a file (one entry per line; lines
starting with `#` and blank lines are ignored):

```
# known management hosts — do not scan
10.0.0.1
10.0.0.2/30

# out-of-scope subnet
172.16.0.0/12
```

```bash
hellhound --target 10.0.0.0/8 --exclude-file ./out-of-scope.txt
```

Both flags can be combined:

```bash
hellhound --target 192.168.0.0/16 \
  --exclude 192.168.1.1 \
  --exclude-file corporate-exclusions.txt
```

#### CSV output and writing to a file

For a CIDR sweep you usually want a persistent artefact you can open in a
spreadsheet or import into a SIEM. Use `--format csv` together with
`--output-file` (`-o`):

```bash
hellhound --target 192.0.2.0/24 --format csv --output-file sweep.csv
```

When `--output-file` is given, nothing is printed to stdout — the output goes
to the file. `--output-file` works with any format (`json`, `text`, or `csv`).

The CSV has a header row followed by one row per matched device. Columns:

```csv
host,port,scheme,vendor,model_class,severity,fingerprint_id,default_creds,username,password,cve,evidence
192.0.2.10,80,http,Hikvision,DVR / NVR / IP Camera,critical,hikvision-dvr,true,admin,12345,,matched Hikvision via title/body; default creds admin:12345 authenticated at /ISAPI/Security/userCheck
192.0.2.20,443,https,HPE Aruba,Enterprise access point,critical,aruba-instant-on,true,admin,default123,CVE-2025-37103,default creds authenticated
192.0.2.11,443,https,Dahua,NVR,high,dahua-nvr,false,,,,matched Dahua fingerprint; default credentials rejected
```

`default_creds` is `true`/`false`. For devices whose default credentials were
rejected (`default_creds` is `false`), the `username` and `password` cells are
empty. The `cve` column lists any CVEs linked to the matched fingerprint,
semicolon-separated when there is more than one (e.g.
`CVE-2024-6047;CVE-2024-11120`); it is empty when the fingerprint has no
associated CVE.

### Retries

IoT devices on flaky consumer broadband or overloaded embedded webservers
frequently drop the first connection. A single attempt then records a false
negative — the device is reachable, hellhound just caught it on a bad moment.

By default hellhound makes a single attempt per request (`--retries 1`),
preserving fast, predictable scans. Raise `--retries` to retry transient
transport failures (timeouts, connection resets) with exponential backoff:

```bash
hellhound --target 192.0.2.0/24 --retries 3
```

`--retries N` is the **total** number of attempts. The backoff before attempt
*N* is `0.5s × (N − 1)`, so the first try is immediate, the second waits 0.5s,
the third 1.0s, and so on. Both the landing-page fetch and the
default-credential check are retried. A response that arrives — even an HTTP
error like `401` — is never retried; only transport-level failures are. If
every attempt fails the host is silently dropped, exactly as with the default.

### Rate limiting

`--concurrency` controls how many requests run *in parallel*; it does not bound
how *fast* requests leave. A high concurrency can overwhelm small embedded
webservers — some cameras watchdog-reboot under burst load — or trip IDS rules
in monitored environments. `--rate-limit N` caps outbound requests to `N` per
second across the whole scan:

```bash
hellhound --target 192.0.2.0/24 --concurrency 50 --rate-limit 5
```

The throttle is a leaky bucket seated **above** the concurrency semaphore:
requests are spaced at least `1 / N` seconds apart regardless of how many
coroutines are ready to fire, so the effective request rate never exceeds the
cap. The default `--rate-limit 0` disables throttling and preserves the original
unbounded behaviour. The cap applies to every outbound request — landing-page
fetches and default-credential checks alike, including retries.

---

## Fingerprint format

Fingerprints live in `hellhound/fingerprints/<set>.yaml`. The default set ships
with 96 device classes. The original Mirai-era set covers Hikvision, Dahua,
MikroTik RouterOS, Ubiquiti, Axis, D-Link, NETGEAR, TP-Link, Foscam, ZyXEL,
AVTECH, and a generic CCTV admin panel. A second tranche covers device classes
actively targeted by 2025-2026 botnets: Reolink and Vivotek cameras, second-gen
Axis cameras, Grandstream phones/APs, HPE Aruba Instant On APs
(CVE-2025-37103), Tenda, ASUS, Linksys WRT and NETGEAR Orbi routers, Amcrest
NVRs, Moxa NPort serial servers, and GeoVision DVRs
(CVE-2024-6047 / CVE-2024-11120). A third tranche covers device classes seen in
2024-2025 mass-exploitation campaigns: TBK DVRs (CVE-2024-3721), TOTOLINK
routers (CVE-2024-7029), Uniview NVRs, Hanwha Wisenet cameras, QNAP and Western
Digital My Cloud NAS appliances, newer-default Hikvision ISAPI cameras
(admin/admin12345), and Cisco RV-series small-business routers. A fourth tranche
covers network-edge and industrial classes from 2024-2025 mass-exploitation
campaigns and Mirai variant target lists: Zyxel ZLD VPN firewalls
(CVE-2023-28771), DrayTek Vigor routers (CVE-2024-41592), Ruckus wireless
controllers (CVE-2023-25717), Edimax IC cameras (CVE-2025-1316), Four-Faith
industrial cellular routers (CVE-2024-12856), Contec SolarView solar gateways
(CVE-2022-29303), AVTECH AVM/AVN cameras (CVE-2024-7029), and OptiLink GPON
ONTs. A fifth tranche covers enterprise edge appliances and internet-facing
servers from the 2023-2025 KEV / mass-exploitation lists: Barracuda Email
Security Gateway (CVE-2023-2868), Cisco IOS XE web UI
(CVE-2023-20198 / CVE-2023-20273), Progress MOVEit Transfer (CVE-2023-34362),
Progress Telerik (CVE-2024-4358), Atlassian Confluence (CVE-2023-22515), Ivanti
Connect Secure (CVE-2023-46805 / CVE-2024-21887), Fortinet FortiGate
(CVE-2024-21762), and SonicWall Secure Mobile Access (CVE-2024-38475). A sixth
tranche covers internet-facing enterprise servers and remote-access appliances
from the 2023-2025 CISA KEV / mass-exploitation lists: Veeam Backup &
Replication (CVE-2024-40711), Citrix NetScaler ADC/Gateway
(CVE-2023-4966 / CVE-2025-5777, CitrixBleed), Progress WS_FTP Server
(CVE-2023-40044), Adobe ColdFusion (CVE-2023-26360), ConnectWise ScreenConnect
(CVE-2024-1709), GeoServer (CVE-2024-36401), Roundcube webmail (CVE-2024-37383),
and PaperCut NG/MF print management (CVE-2023-27350). A seventh tranche covers
internet-facing enterprise web applications and management consoles from the
2022-2025 CISA KEV / mass-exploitation lists: Zoho ManageEngine
(CVE-2022-47966), Citrix ShareFile (CVE-2023-24489), Apache OFBiz
(CVE-2023-49070 / CVE-2024-45195), Openfire XMPP (CVE-2023-32315), SolarWinds
Orion / Web Help Desk (CVE-2024-28987), Langflow (CVE-2025-3248), Apache Tomcat
Manager (CVE-2025-24813), and Cacti (CVE-2022-46169). An eighth tranche covers
enterprise edge appliances and internet-facing applications mass-exploited
across the 2024-2025 CISA KEV / ransomware landscape: Progress WhatsUp Gold
(CVE-2024-6670 / CVE-2024-4885), Apache Struts 2 (CVE-2024-53677), Palo Alto
PAN-OS GlobalProtect (CVE-2024-3400), Ivanti Avalanche (CVE-2023-32560), VMware
vCenter Server (CVE-2024-38812), CrushFTP (CVE-2024-4040), CyberPanel
(CVE-2024-51378), and Array Networks AG/vxAG SSL VPN (CVE-2023-28461). A ninth
tranche covers internet-facing enterprise appliances, NAS devices, file servers
and web platforms mass-exploited across the 2024-2025 CISA KEV / ransomware
landscape: Fortinet FortiManager (CVE-2024-47575, "FortiJump"), Sophos Firewall
(CVE-2022-1040), D-Link DNS-series NAS (CVE-2024-3273), Progress Kemp LoadMaster
(CVE-2024-1212), Synacor Zimbra Collaboration (CVE-2024-45519), Rejetto HTTP
File Server (CVE-2024-23692), GitLab Community Edition (CVE-2023-7028), and
NextGen Mirth Connect (CVE-2023-43208). A tenth tranche covers internet-facing
enterprise appliances, gateways and management consoles mass-exploited across
the 2023-2025 CISA KEV / ransomware landscape: Ivanti Endpoint Manager Mobile /
MobileIron Core (CVE-2023-35078), ownCloud (CVE-2023-49103), Acronis Cyber
Infrastructure (CVE-2023-45249), Qlik Sense (CVE-2023-48365), Zyxel NAS
(CVE-2023-27992), HPE OneView, Commvault Command Center (CVE-2025-34028), and
SysAid (CVE-2023-47246). An eleventh tranche covers internet-facing managed
file-transfer servers, storage appliances, hypervisor and cloud-networking
consoles, e-commerce admin panels and ADC management UIs mass-exploited across
the 2024-2025 CISA KEV / ransomware landscape: Cleo Harmony / VLTrader / LexiCom
(CVE-2024-50623, Cl0p), TerraMaster NAS (CVE-2024-22366), VMware ESXi host
client (ESXiArgs), Palo Alto Expedition (CVE-2024-5910), Magento / Adobe
Commerce (CVE-2024-34102, CosmicSting), Aviatrix Controller (CVE-2024-50603),
F5 BIG-IP TMUI (CVE-2023-46747), and Kibana (CVE-2024-37287).

Each file has a top-level `fingerprints` list. An entry:

```yaml
fingerprints:
  - id: hikvision-dvr            # unique identifier for this fingerprint
    vendor: Hikvision            # manufacturer
    model_class: DVR / NVR / IP Camera   # device class
    severity: critical           # low | medium | high | critical
    description: optional human-readable note
    cve:                         # optional list of related CVE IDs
      - CVE-2025-37103
    match:                       # how to recognise the device (AND semantics)
      path: /                    # page to fetch for matching (default /)
      http_title: Hikvision      # case-insensitive substring of <title>  (optional)
      body_contains: login.asp   # case-insensitive substring of body      (optional)
      header_contains:           # response header name -> substring        (optional)
        server: App-webs
      status_code: 200           # exact status code constraint            (optional)
    default_credentials:         # one or more pairs to try, in order
      - {username: admin, password: "12345"}
    auth:                        # how to verify a credential
      type: basic                # basic (HTTP Basic) | form (HTML form POST)
      path: /ISAPI/Security/userCheck
      # form auth additionally accepts:
      #   method: POST
      #   username_field: username
      #   password_field: password
      #   success_status: [200]
      #   failure_body_contains: error
      #   extra_fields: { key: value }
```

Matching rules:

- `cve` is optional: a list of CVE IDs (or a single string) linking the device
  class to published advisories. It is surfaced on every finding for that
  fingerprint, across all output formats, and defaults to empty when omitted.
- A `match` block uses **AND semantics** — every field you specify must match.
- At least one of `http_title`, `body_contains`, or `header_contains` is
  required; an entry with no positive condition never matches (so a malformed
  fingerprint can't flag every host on the network).
- `auth.type: basic` sends HTTP Basic credentials and treats a `success_status`
  response as authenticated.
- `auth.type: form` POSTs the credential fields and treats a `success_status`
  response that does **not** contain `failure_body_contains` as authenticated.

Add a new device by appending an entry. Load an alternate set with
`--fingerprint-set <name>` (the file must be `hellhound/fingerprints/<name>.yaml`).

### Custom fingerprint directory

To keep a private fingerprint set — for proprietary or unreleased devices —
without patching hellhound, point `--fingerprint-dir` at a directory containing
a `<set>.yaml` named to match `--fingerprint-set` (so `default.yaml` for the
default set). hellhound always loads the bundled database as the base, then
merges your file on top:

- A custom entry whose `id` matches a bundled entry **replaces** it in place
  (override a shipped fingerprint without forking the database).
- A custom entry with a new `id` is **appended** after the bundled entries.
- Bundled-only entries are preserved.

```bash
# ~/fp/default.yaml holds your private/extra fingerprints
hellhound --target 192.0.2.0/24 --fingerprint-dir ~/fp
```

If the directory is missing or has no matching `<set>.yaml`, hellhound exits
with an error rather than silently ignoring the flag.

---

## Scope (v0.1)

In scope: HTTP/HTTPS fingerprinting and default-credential checking over a CIDR
range or single host, JSON/text/CSV output (to stdout or a file), a YAML
fingerprint database.

Deliberately **out of scope** for v0.1: Telnet/SSH scanning, brute-forcing
non-default credentials, any active exploitation, Shodan integration, and a web
UI. hellhound stays detection-only.

---

## Development

```bash
pip install -e '.[test]'

# fast unit + smoke tests (no network, no Docker):
pytest -m "not integration"

# optional live test — spins up a container masquerading as a Hikvision DVR
# (requires Docker; auto-skips if unavailable):
pytest -m integration
```

---

## License

MIT — see [LICENSE](LICENSE).
