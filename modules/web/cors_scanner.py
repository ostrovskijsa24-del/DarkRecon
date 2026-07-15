import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import urlparse

import aiohttp


@dataclass
class CORSCheck:
    name: str
    origin_sent: str
    vulnerable: bool
    severity: str = "low"  # low / medium / high / critical
    description: str = ""
    acao: str = ""   # Access-Control-Allow-Origin
    acac: str = ""   # Access-Control-Allow-Credentials
    acam: str = ""   # Access-Control-Allow-Methods
    evidence: str = ""


@dataclass
class CORSReport:
    target: str
    checks: List[CORSCheck] = field(default_factory=list)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for c in self.checks if c.vulnerable)


class CORSScanner:
    HEADERS_BASE = {
        "User-Agent": "DarkRecon/1.0 (CTF-AutoTool)",
        "Accept": "*/*",
    }

    def __init__(
        self,
        target_url: str,
        timeout: float = 8.0,
        custom_headers: Optional[Dict[str, str]] = None,
        cookies: Optional[str] = None,
    ):
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = "http://" + target_url
        self.target = target_url.rstrip("/")
        self.target_domain = parsed.netloc.split(":")[0]
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.custom_headers = custom_headers or {}
        self.cookies = cookies

    async def scan(self) -> CORSReport:
        report = CORSReport(target=self.target)
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self.HEADERS_BASE,
        ) as session:
            checks = await asyncio.gather(
                self._check_null_origin(session),
                self._check_origin_reflection(session),
                self._check_wildcard(session),
                self._check_subdomain_spoof(session),
                self._check_regex_bypass_dot(session),
                self._check_regex_bypass_no_dot(session),
                self._check_http_downgrade(session),
                self._check_preflight(session),
            )
            report.checks = [c for c in checks if c is not None]
        return report

    async def _request(self, session: aiohttp.ClientSession, origin: str, method: str = "GET") -> Optional[aiohttp.ClientResponse]:
        headers = dict(self.custom_headers)
        headers["Origin"] = origin
        if self.cookies:
            headers["Cookie"] = self.cookies
        try:
            if method == "OPTIONS":
                headers["Access-Control-Request-Method"] = "PUT"
                headers["Access-Control-Request-Headers"] = "X-Custom"
                return await session.options(self.target, headers=headers)
            return await session.get(self.target, headers=headers)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None

    def _extract(self, resp: aiohttp.ClientResponse) -> tuple:
        h = resp.headers
        return (
            h.get("Access-Control-Allow-Origin", ""),
            h.get("Access-Control-Allow-Credentials", ""),
            h.get("Access-Control-Allow-Methods", ""),
        )

    async def _check_null_origin(self, session) -> CORSCheck:
        resp = await self._request(session, "null")
        if not resp:
            return CORSCheck("null origin", "null", False, description="No response")
        acao, acac, acam = self._extract(resp)
        vulnerable = acao.lower() == "null"
        return CORSCheck(
            name="null Origin",
            origin_sent="null",
            vulnerable=vulnerable,
            severity="high" if vulnerable and acac.lower() == "true" else ("medium" if vulnerable else "low"),
            description="Server accepts Origin: null — sandboxed iframes / data: URIs can read response",
            acao=acao, acac=acac, acam=acam,
        )

    async def _check_origin_reflection(self, session) -> CORSCheck:
        evil = "https://evil-attacker.com"
        resp = await self._request(session, evil)
        if not resp:
            return CORSCheck("origin reflection", evil, False, description="No response")
        acao, acac, acam = self._extract(resp)
        vulnerable = acao == evil
        return CORSCheck(
            name="Origin reflection",
            origin_sent=evil,
            vulnerable=vulnerable,
            severity="critical" if vulnerable and acac.lower() == "true" else ("high" if vulnerable else "low"),
            description="Server reflects any Origin — attacker can steal data cross-origin",
            acao=acao, acac=acac, acam=acam,
        )

    async def _check_wildcard(self, session) -> CORSCheck:
        evil = "https://evil-attacker.com"
        resp = await self._request(session, evil)
        if not resp:
            return CORSCheck("wildcard ACAO", evil, False, description="No response")
        acao, acac, acam = self._extract(resp)
        vulnerable = acao.strip() == "*"
        # Wildcard + credentials is actually blocked by browsers, but still misconfig
        return CORSCheck(
            name="Wildcard ACAO",
            origin_sent=evil,
            vulnerable=vulnerable,
            severity="medium" if vulnerable else "low",
            description="Access-Control-Allow-Origin: * — any site can read response (no credentials)",
            acao=acao, acac=acac, acam=acam,
        )

    async def _check_subdomain_spoof(self, session) -> CORSCheck:
        if not self.target_domain:
            return CORSCheck("subdomain spoof", "", False, description="No target domain")
        evil = f"https://evil.{self.target_domain}"
        resp = await self._request(session, evil)
        if not resp:
            return CORSCheck("subdomain spoof", evil, False, description="No response")
        acao, acac, acam = self._extract(resp)
        vulnerable = acao == evil or acao.endswith(f".{self.target_domain}")
        return CORSCheck(
            name="Subdomain spoof",
            origin_sent=evil,
            vulnerable=vulnerable,
            severity="high" if vulnerable and acac.lower() == "true" else ("medium" if vulnerable else "low"),
            description=f"Server trusts any subdomain of {self.target_domain} — attacker who controls one subdomain can read responses",
            acao=acao, acac=acac, acam=acam,
        )

    async def _check_regex_bypass_dot(self, session) -> CORSCheck:
        if not self.target_domain or "." not in self.target_domain:
            return CORSCheck("regex bypass (suffix)", "", False, description="No target domain")
        evil = f"https://{self.target_domain}.evil.com"
        resp = await self._request(session, evil)
        if not resp:
            return CORSCheck("regex bypass (suffix)", evil, False, description="No response")
        acao, acac, acam = self._extract(resp)
        vulnerable = acao == evil
        return CORSCheck(
            name="Regex bypass (suffix with .evil.com)",
            origin_sent=evil,
            vulnerable=vulnerable,
            severity="high" if vulnerable and acac.lower() == "true" else ("medium" if vulnerable else "low"),
            description="Whitelist regex likely missing \\ before the dot — attacker.com.target.com accepted",
            acao=acao, acac=acac, acam=acam,
        )

    async def _check_regex_bypass_no_dot(self, session) -> CORSCheck:
        if not self.target_domain:
            return CORSCheck("regex bypass (no dot)", "", False, description="No target domain")
        evil = f"https://{self.target_domain.replace('.', '')}evil.com"
        resp = await self._request(session, evil)
        if not resp:
            return CORSCheck("regex bypass (no dot)", evil, False, description="No response")
        acao, acac, acam = self._extract(resp)
        vulnerable = acao == evil
        return CORSCheck(
            name="Regex bypass (domain concatenated)",
            origin_sent=evil,
            vulnerable=vulnerable,
            severity="high" if vulnerable and acac.lower() == "true" else ("medium" if vulnerable else "low"),
            description="Whitelist accepts targetdomainevil.com — missing anchor $ or dot in regex",
            acao=acao, acac=acac, acam=acam,
        )

    async def _check_http_downgrade(self, session) -> CORSCheck:
        if not self.target_domain:
            return CORSCheck("http downgrade", "", False, description="No target domain")
        evil = f"http://{self.target_domain}"
        resp = await self._request(session, evil)
        if not resp:
            return CORSCheck("http downgrade", evil, False, description="No response")
        acao, acac, acam = self._extract(resp)
        vulnerable = acao == evil
        return CORSCheck(
            name="HTTP downgrade (http:// trusted)",
            origin_sent=evil,
            vulnerable=vulnerable,
            severity="high" if vulnerable else "low",
            description="Server trusts http:// version — MITM can inject script and read responses",
            acao=acao, acac=acac, acam=acam,
        )

    async def _check_preflight(self, session) -> CORSCheck:
        evil = "https://evil-attacker.com"
        resp = await self._request(session, evil, method="OPTIONS")
        if not resp:
            return CORSCheck("preflight OPTIONS", evil, False, description="No response")
        acao, acac, acam = self._extract(resp)
        dangerous_methods = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}
        allowed = {m.strip().upper() for m in acam.split(",") if m.strip()}
        dangerous_allowed = allowed & dangerous_methods
        vulnerable = acao == evil or acao == "*"
        evidence = f"Allowed methods: {acam}" if acam else ""
        if dangerous_allowed:
            evidence += f" (DANGEROUS: {', '.join(dangerous_allowed)})"
        return CORSCheck(
            name="Preflight (OPTIONS) analysis",
            origin_sent=evil,
            vulnerable=vulnerable or bool(dangerous_allowed),
            severity="medium" if (vulnerable or dangerous_allowed) else "low",
            description="CORS pre-flight allows dangerous HTTP methods cross-origin" if dangerous_allowed else "CORS pre-flight response analysis",
            acao=acao, acac=acac, acam=acam,
            evidence=evidence,
        )