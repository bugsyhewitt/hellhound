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
    ) -> list[Finding]:
        """Scan all targets across all ports concurrently.

        *exclusions* is an optional list of networks (built by
        :meth:`parse_exclusions`) whose hosts are silently skipped after target
        expansion.
        """
        hosts = self.expand_targets(targets)
        if exclusions:
            hosts = [h for h in hosts if not self.is_excluded(h, exclusions)]
        async with self._client() as client:
            tasks = [self._scan_host(client, host, ports) for host in hosts]
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
            try:
                return await request()
            except httpx.HTTPError:
                if attempt >= self._retries:
                    return None
        return None
