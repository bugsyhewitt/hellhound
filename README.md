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
| `--target`, `-t` | CIDR range or single IP/host. Repeat for multiple targets. | *(required)* |
| `--ports`, `-p` | Comma-separated ports to probe. | `80,443,8080,8443` |
| `--fingerprint-set`, `-f` | Name of the fingerprint set under `hellhound/fingerprints/`. | `default` |
| `--format` | `json`, `text`, or `csv`. | `json` |
| `--output-file`, `-o` | Write output to this path instead of stdout. | *(stdout)* |
| `--timeout` | Per-request timeout (seconds). | `5.0` |
| `--concurrency` | Max concurrent requests. | `50` |
| `--exclude`, `-e` | Exclude a CIDR or IP from scanning. Repeatable. | *(none)* |
| `--exclude-file` | Path to a file of CIDR/IP exclusions (one per line, `#` comments). | *(none)* |

### Output

JSON output groups a summary with per-device findings:

```json
{
  "summary": {
    "devices_matched": 1,
    "devices_with_default_creds": 1
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
      "evidence": "matched Hikvision via title/body; default creds admin:12345 authenticated at /ISAPI/Security/userCheck"
    }
  ]
}
```

A finding with `"default_creds": true` is the actionable result: that device
still accepts the listed default credentials and should be reconfigured.

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
host,port,scheme,vendor,model_class,severity,fingerprint_id,default_creds,username,password,evidence
192.0.2.10,80,http,Hikvision,DVR / NVR / IP Camera,critical,hikvision-dvr,true,admin,12345,matched Hikvision via title/body; default creds admin:12345 authenticated at /ISAPI/Security/userCheck
192.0.2.11,443,https,Dahua,NVR,high,dahua-nvr,false,,,matched Dahua fingerprint; default credentials rejected
```

`default_creds` is `true`/`false`. For devices whose default credentials were
rejected (`default_creds` is `false`), the `username` and `password` cells are
empty.

---

## Fingerprint format

Fingerprints live in `hellhound/fingerprints/<set>.yaml`. The default set ships
with 24 IoT device classes. The original Mirai-era set covers Hikvision, Dahua,
MikroTik RouterOS, Ubiquiti, Axis, D-Link, NETGEAR, TP-Link, Foscam, ZyXEL,
AVTECH, and a generic CCTV admin panel. A second tranche covers device classes
actively targeted by 2025-2026 botnets: Reolink and Vivotek cameras, second-gen
Axis cameras, Grandstream phones/APs, HPE Aruba Instant On APs
(CVE-2025-37103), Tenda, ASUS, Linksys WRT and NETGEAR Orbi routers, Amcrest
NVRs, Moxa NPort serial servers, and GeoVision DVRs
(CVE-2024-6047 / CVE-2024-11120).

Each file has a top-level `fingerprints` list. An entry:

```yaml
fingerprints:
  - id: hikvision-dvr            # unique identifier for this fingerprint
    vendor: Hikvision            # manufacturer
    model_class: DVR / NVR / IP Camera   # device class
    severity: critical           # low | medium | high | critical
    description: optional human-readable note
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
