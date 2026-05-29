"""The scan engine: probe hosts, match fingerprints, check default creds.

Detection-only by design. For each target host/port hellhound:

1. fetches the device landing page (and any per-fingerprint match path),
2. matches the response against the loaded fingerprints,
3. for every match, tries that fingerprint's known default credentials,
4. records a Finding — flagged when default creds authenticate.

It never attempts non-default credentials and never performs any action
beyond an authentication check. See README's ethical-use notice.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field

import httpx

from .fingerprint import AuthCheck, Credential, Fingerprint

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(body: str) -> str:
    """Pull the <title> text out of an HTML body, trimmed. '' if absent."""
    match = _TITLE_RE.search(body or "")
    if not match:
        return ""
    return match.group(1).strip()


@dataclass
class Finding:
    """One device matched against the fingerprint database.

    ``default_creds`` is True only when a default credential pair authenticated.
    """

    host: str
    port: int
    scheme: str
    url: str
    fingerprint_id: str
    vendor: str
    model_class: str
    severity: str
    default_creds: bool
    matched_credential: Credential | None
    evidence: str
    cve: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        cred = (
            {"username": self.matched_credential.username, "password": self.matched_credential.password}
            if self.matched_credential
            else None
        )
        data = asdict(self)
        data["matched_credential"] = cred
        data["cve"] = list(self.cve)
        return data


@dataclass
class ScanProgress:
    """A snapshot of scan progress, passed to a progress callback per host.

    Reported after each host finishes so a caller can render a live status line
    (e.g. to stderr) during a long CIDR sweep. ``hosts_done`` counts hosts whose
    scan has completed, ``hosts_total`` is the post-exclusion host count, and
    ``findings_with_default_creds`` is the running tally of confirmed exposures.
    """

    hosts_done: int
    hosts_total: int
    findings_with_default_creds: int


class Scanner:
    """Async scanner over a set of fingerprints.

    A ``transport`` may be injected for testing (httpx.MockTransport); in
    production the default transport performs real network requests.
    """

    def __init__(
        self,
        *,
        fingerprints: list[Fingerprint],
        transport: httpx.BaseTransport | None = None,
        timeout: float = 5.0,
        concurrency: int = 50,
        verify_tls: bool = False,
        retries: int = 1,
        backoff: float = 0.5,
        rate_limit: float = 0.0,
    ) -> None:
        self.fingerprints = fingerprints
        self._transport = transport
        self._timeout = timeout
        self._verify_tls = verify_tls
        self._semaphore = asyncio.Semaphore(concurrency)
        # ``retries`` is the total number of attempts per request. 1 (the
        # default) means a single try and preserves the original behaviour;
        # 2 means one silent retry after a transport failure, and so on. A
        # value below 1 is clamped to 1.
        self._retries = max(1, retries)
        # Base backoff in seconds; the delay before attempt N (1-indexed) is
        # ``backoff * (N - 1)`` — i.e. 0s before the first try, then 0.5s,
        # 1.0s, ... by default.
        self._backoff = max(0.0, backoff)
        # ``rate_limit`` is a cap on outbound requests per second across the
        # whole scan. 0 (the default) disables throttling. The throttle is a
        # leaky-bucket: requests are spaced at least ``1 / rate_limit`` seconds
        # apart, seated above the concurrency semaphore so a high concurrency
        # never exceeds the configured rate. This protects fragile embedded
        # webservers (some cameras watchdog-reboot under burst load) and avoids
        # tripping IDS rules in monitored environments.
        self._rate_limit = max(0.0, rate_limit)
        self._min_interval = 1.0 / self._rate_limit if self._rate_limit > 0 else 0.0
        self._rate_lock = asyncio.Lock()
        # Monotonic timestamp at which the next request is allowed to fire.
        self._next_allowed = 0.0
        # Number of hosts probed by the most recent ``scan`` call, after target
        # expansion and exclusion filtering. ``None`` until the first scan. The
        # CLI reads it to report the sweep denominator ("matched X of Y
        # scanned") in the output summary, which is otherwise invisible once
        # the transient stderr progress line is off (e.g. piped to a file).
        self.last_hosts_scanned: int | None = None

    # ------------------------------------------------------------------ exclusions

    @staticmethod
    def parse_exclusions(
        exclude: list[str] | None = None,
        exclude_file: str | None = None,
    ) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse ``--exclude`` entries and/or an ``--exclude-file`` into networks.

        Each entry may be a single IP (e.g. ``10.0.0.5``) or a CIDR
        (e.g. ``10.0.0.0/8``).  Lines in ``exclude_file`` beginning with ``#``
        and blank lines are ignored.
        """
        raw: list[str] = list(exclude or [])

        if exclude_file:
            with open(exclude_file, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    raw.append(line)

        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for entry in raw:
            networks.append(ipaddress.ip_network(entry, strict=False))
        return networks

    @staticmethod
    def is_excluded(
        host: str,
        exclusions: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> bool:
        """Return True if *host* (a string IP address) falls within any exclusion network."""
        if not exclusions:
            return False
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            # bare hostname — cannot match a CIDR exclusion; don't exclude it
            return False
        return any(addr in net for net in exclusions)

    # ------------------------------------------------------------------ targets
    @staticmethod
    def expand_targets(targets: list[str]) -> list[str]:
        """Expand CIDR ranges and single IPs/hosts into a deduped host list.

        CIDR networks expand to their usable host addresses. Bare hosts and
        single IPs pass through unchanged. Order is preserved on first sight.
        """
        seen: set[str] = set()
        ordered: list[str] = []

        def add(host: str) -> None:
            if host not in seen:
                seen.add(host)
                ordered.append(host)

        for target in targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError:
                # not an IP/CIDR -> treat as a hostname
                add(target)
                continue

            if network.num_addresses == 1:
                add(str(network.network_address))
            else:
                for host in network.hosts():
                    add(str(host))
        return ordered

    # ------------------------------------------------------------------ scanning
    async def scan(
        self,
        targets: list[str],
        ports: list[int],
        exclusions: list[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
        progress_callback: Callable[[ScanProgress], None] | None = None,
    ) -> list[Finding]:
        """Scan all targets across all ports concurrently.

        *exclusions* is an optional list of networks (built by
        :meth:`parse_exclusions`) whose hosts are silently skipped after target
        expansion.

        *progress_callback*, when supplied, is invoked once per completed host
        with a :class:`ScanProgress` snapshot (hosts done, total hosts, and the
        running count of confirmed default-credential findings). It lets a caller
        emit a live progress line during long sweeps without the scanner needing
        to know about stderr or any output format. The callback runs on the
        event loop between host completions; it must be cheap and non-blocking.
        """
        hosts = self.expand_targets(targets)
        if exclusions:
            hosts = [h for h in hosts if not self.is_excluded(h, exclusions)]

        total = len(hosts)
        # Record the post-exclusion host count so the caller can report the
        # sweep denominator after the scan completes.
        self.last_hosts_scanned = total
        done = 0
        flagged = 0

        async def run_host(host: str) -> list[Finding]:
            nonlocal done, flagged
            host_findings = await self._scan_host(client, host, ports)
            done += 1
            flagged += sum(1 for f in host_findings if f.default_creds)
            if progress_callback is not None:
                progress_callback(
                    ScanProgress(
                        hosts_done=done,
                        hosts_total=total,
                        findings_with_default_creds=flagged,
                    )
                )
            return host_findings

        async with self._client() as client:
            tasks = [run_host(host) for host in hosts]
            results = await asyncio.gather(*tasks)
        return [finding for host_findings in results for finding in host_findings]

    async def scan_host(self, host: str, ports: list[int]) -> list[Finding]:
        """Scan a single host. Convenience wrapper that owns its client."""
        async with self._client() as client:
            return await self._scan_host(client, host, ports)

    def _client(self) -> httpx.AsyncClient:
        kwargs: dict = {
            "timeout": self._timeout,
            "verify": self._verify_tls,
            "follow_redirects": True,
            "headers": {"User-Agent": "hellhound/0.1"},
        }
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return httpx.AsyncClient(**kwargs)

    async def _scan_host(
        self, client: httpx.AsyncClient, host: str, ports: list[int]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for port in ports:
            scheme = "https" if port in (443, 8443) else "http"
            base = f"{scheme}://{host}:{port}"
            async with self._semaphore:
                response = await self._safe_get(client, f"{base}/")
            if response is None:
                continue

            body = response.text
            title = extract_title(body)
            headers = {k: v for k, v in response.headers.items()}

            for fp in self.fingerprints:
                if not fp.match.matches(
                    status=response.status_code,
                    title=title,
                    body=body,
                    headers=headers,
                ):
                    continue
                finding = await self._check_credentials(client, base, host, port, scheme, fp, title)
                findings.append(finding)
        return findings

    async def _check_credentials(
        self,
        client: httpx.AsyncClient,
        base: str,
        host: str,
        port: int,
        scheme: str,
        fp: Fingerprint,
        title: str,
    ) -> Finding:
        matched: Credential | None = None
        for cred in fp.credentials:
            async with self._semaphore:
                ok = await self._try_auth(client, base, fp.auth, cred)
            if ok:
                matched = cred
                break

        if matched is not None:
            evidence = (
                f"matched {fp.vendor} via title/body; default creds "
                f"{matched.username}:{matched.password} authenticated at "
                f"{fp.auth.path}"
            )
        else:
            evidence = (
                f"matched {fp.vendor} fingerprint (title={title!r}); "
                f"default credentials rejected"
            )

        return Finding(
            host=host,
            port=port,
            scheme=scheme,
            url=f"{base}/",
            fingerprint_id=fp.id,
            vendor=fp.vendor,
            model_class=fp.model_class,
            severity=fp.severity,
            default_creds=matched is not None,
            matched_credential=matched,
            evidence=evidence,
            cve=list(fp.cve),
        )

    async def _try_auth(
        self, client: httpx.AsyncClient, base: str, auth: AuthCheck, cred: Credential
    ) -> bool:
        url = f"{base}{auth.path}"

        async def request() -> httpx.Response:
            if auth.type == "basic":
                return await client.get(url, auth=(cred.username, cred.password))
            # form
            data = {
                auth.username_field: cred.username,
                auth.password_field: cred.password,
                **auth.extra_fields,
            }
            return await client.request(auth.method, url, data=data)

        response = await self._with_retries(request)
        if response is None:
            return False

        if response.status_code not in auth.success_status:
            return False
        if auth.failure_body_contains and auth.failure_body_contains.lower() in response.text.lower():
            return False
        return True

    async def _safe_get(self, client: httpx.AsyncClient, url: str) -> httpx.Response | None:
        return await self._with_retries(lambda: client.get(url))

    async def _with_retries(
        self, request: Callable[[], Awaitable[httpx.Response]]
    ) -> httpx.Response | None:
        """Run *request* up to ``self._retries`` times with exponential backoff.

        IoT devices on flaky broadband or overloaded embedded webservers often
        drop the first connection, producing a false negative. Retrying a
        transient transport error a couple of times recovers many of these
        without materially slowing a scan.

        Returns the first successful response, or ``None`` if every attempt
        raised an ``httpx.HTTPError`` (timeouts, connection resets, etc.).
        The backoff before attempt N (1-indexed) is ``self._backoff * (N - 1)``,
        so the first attempt is immediate.
        """
        for attempt in range(1, self._retries + 1):
            if attempt > 1 and self._backoff:
                await asyncio.sleep(self._backoff * (attempt - 1))
            await self._throttle()
            try:
                return await request()
            except httpx.HTTPError:
                if attempt >= self._retries:
                    return None
        return None

    async def _throttle(self) -> None:
        """Block until the configured requests-per-second rate permits a call.

        Implements a leaky-bucket: each acquisition reserves the next slot at
        ``last_slot + min_interval`` and sleeps until then. Acquisitions are
        serialised by a lock so concurrent coroutines (up to the concurrency
        semaphore) are paced rather than bursting. A ``rate_limit`` of 0 makes
        this a no-op, preserving the original unthrottled behaviour.
        """
        if self._min_interval <= 0.0:
            return
        async with self._rate_lock:
            now = time.monotonic()
            # The next slot is the later of "right now" and "one interval after
            # the previously reserved slot".
            slot = max(now, self._next_allowed)
            self._next_allowed = slot + self._min_interval
            wait = slot - now
        if wait > 0:
            await asyncio.sleep(wait)
