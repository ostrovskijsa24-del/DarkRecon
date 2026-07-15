import asyncio
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set
from urllib.parse import urlparse

import aiohttp


@dataclass
class SubdomainResult:
    subdomain: str
    resolved_ip: str = ""
    http_status: Optional[int] = None
    http_title: str = ""
    source: str = ""
    error: str = ""

    @property
    def alive(self) -> bool:
        return self.http_status is not None or bool(self.resolved_ip)


@dataclass
class SubdomainReport:
    target: str
    results: List[SubdomainResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def alive_count(self) -> int:
        return sum(1 for r in self.results if r.alive)


class SubdomainEnumerator:
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 DarkRecon/1.0",
        "Accept": "application/json, text/html, */*",
    }

    def __init__(self, timeout: float = 6.0, concurrency: int = 25, check_http: bool = True):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.concurrency = concurrency
        self.check_http = check_http
        self._sem = asyncio.Semaphore(concurrency)

    def _extract_domain(self, target: str) -> str:
        target = target.strip().replace("\\", "/")
        if target.startswith(("http://", "https://")):
            return urlparse(target).netloc.split(":")[0].lower()
        if "/" in target:
            target = target.split("/")[0]
        return target.lower()

    async def scan(self, target: str) -> SubdomainReport:
        domain = self._extract_domain(target)
        report = SubdomainReport(target=domain)
        if not domain or "." not in domain:
            report.errors.append(f"Некорректный домен: {target}")
            return report

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self.HEADERS,
        ) as session:
            found: Set[str] = set()
            sources_meta: Dict[str, str] = {}

            await asyncio.gather(
                self._crt_sh(session, domain, found, sources_meta, report),
                self._hackertarget(session, domain, found, sources_meta, report),
                self._alienvault(session, domain, found, sources_meta, report),
                return_exceptions=True,
            )

            if not found:
                if not report.errors:
                    report.errors.append("Ни один источник не вернул поддомены")
                return report

            tasks = [
                self._probe(session, sd, sources_meta.get(sd, "unknown"), report)
                for sd in sorted(found)
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        report.results.sort(key=lambda r: (not r.alive, r.subdomain))
        return report

    async def _crt_sh(self, session, domain, found, meta, report):
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    report.errors.append(f"crt.sh: HTTP {resp.status}")
                    return
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    report.errors.append("crt.sh: некорректный JSON")
                    return
                for entry in data or []:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower().lstrip("*.")
                        if line and line.endswith(domain) and "*" not in line:
                            found.add(line)
                            meta[line] = "crt.sh"
        except asyncio.TimeoutError:
            report.errors.append("crt.sh: таймаут")
        except Exception as e:
            report.errors.append(f"crt.sh: {type(e).__name__}")

    async def _hackertarget(self, session, domain, found, meta, report):
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return
                text = await resp.text(errors="ignore")
                if "error" in text.lower() or not text.strip():
                    return
                for line in text.splitlines():
                    if "," not in line:
                        continue
                    host = line.split(",")[0].strip().lower()
                    if host.endswith(domain) and re.match(r"^[a-z0-9.\-]+$", host):
                        found.add(host)
                        meta.setdefault(host, "HackerTarget")
        except Exception as e:
            report.errors.append(f"HackerTarget: {type(e).__name__}")

    async def _alienvault(self, session, domain, found, meta, report):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return
                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    return
                for record in data.get("passive_dns", []):
                    host = record.get("hostname", "").lower()
                    if host.endswith(domain) and re.match(r"^[a-z0-9.\-]+$", host):
                        found.add(host)
                        meta.setdefault(host, "AlienVault")
        except Exception as e:
            report.errors.append(f"AlienVault: {type(e).__name__}")

    async def _probe(self, session, subdomain, source, report):
        result = SubdomainResult(subdomain=subdomain, source=source)

        try:
            loop = asyncio.get_event_loop()
            ip = await asyncio.wait_for(
                loop.run_in_executor(None, self._resolve, subdomain),
                timeout=3.0,
            )
            result.resolved_ip = ip or ""
        except asyncio.TimeoutError:
            result.resolved_ip = ""
        except Exception:
            result.resolved_ip = ""

        if self.check_http and result.resolved_ip:
            async with self._sem:
                for scheme in ("https", "http"):
                    try:
                        url = f"{scheme}://{subdomain}/"
                        async with session.get(url, allow_redirects=True, timeout=self.timeout) as resp:
                            result.http_status = resp.status
                            if "text/html" in resp.headers.get("Content-Type", ""):
                                try:
                                    body = await resp.text(errors="ignore")
                                    m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
                                    if m:
                                        result.http_title = m.group(1).strip()[:80]
                                except Exception:
                                    pass
                            break
                    except Exception:
                        continue

        report.results.append(result)

    @staticmethod
    def _resolve(host: str) -> Optional[str]:
        import socket
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None