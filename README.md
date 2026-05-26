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
| `--format` | `json` or `text`. | `json` |
| `--timeout` | Per-request timeout (seconds). | `5.0` |
| `--concurrency` | Max concurrent requests. | `50` |

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

---

## Fingerprint format

Fingerprints live in `hellhound/fingerprints/<set>.yaml`. The default set ships
with 12 well-known IoT device classes (Hikvision, Dahua, MikroTik RouterOS,
Ubiquiti, Axis, D-Link, NETGEAR, TP-Link, Foscam, ZyXEL, AVTECH, and a generic
CCTV admin panel).

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
range or single host, JSON/text output, a YAML fingerprint database.

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
