import asyncio
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urlparse

import aiohttp


SUSPICIOUS_PATTERNS = [
    ("Флаги и секреты", re.compile(r"(flag|secret|token|password|passwd|key|credential)", re.I)),
    ("Бэкапы", re.compile(r"(\.bak|\.old|\.backup|\.save|\.orig|\.copy|~$|\.swp)", re.I)),
    ("Система контроля версий", re.compile(r"(\.git/|\.svn/|\.hg/|\.bzr/)", re.I)),
    ("Конфиги и .env", re.compile(r"(\.env(\.|$)|wp-config|\.htaccess|web\.config|\.npmrc|\.pypirc|credentials)", re.I)),
    ("Базы данных", re.compile(r"(\.sql|\.sqlite|\.db|dump\.|database)", re.I)),
    ("Архивы", re.compile(r"(\.zip|\.tar|\.gz|\.rar|\.7z|\.tgz)", re.I)),
    ("Приватные ключи", re.compile(r"(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.pem|\.key|private)", re.I)),
    ("Админ-панели", re.compile(r"(/admin|/manager|/cpanel|/phpmyadmin|/console|/dashboard)", re.I)),
    ("API и dev", re.compile(r"(/api/|/dev/|/test/|/staging/|/debug/|/internal/)", re.I)),
    ("Документация", re.compile(r"(\.log|\.txt|\.md|readme|changelog|phpinfo|server-status)", re.I)),
]


@dataclass
class ArchivedURL:
    url: str
    timestamp: str
    status: int
    category: str = ""
    match: str = ""


@dataclass
class WaybackReport:
    target: str
    total_snapshots: int = 0
    unique_urls: int = 0
    suspicious: List[ArchivedURL] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    flags_found: List[str] = field(default_factory=list)


class WaybackAnalyzer:
    HEADERS = {
        "User-Agent": "DarkRecon/1.0 (CTF-AutoTool)",
        "Accept": "application/json",
    }

    def __init__(self, timeout: float = 30.0, flag_prefix: str = ""):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.flag_prefix = flag_prefix.strip()
        self.FLAG_PATTERN = None
        if self.flag_prefix:
            try:
                self.FLAG_PATTERN = re.compile(rf"{re.escape(self.flag_prefix)}\{{[^}}]+\}}")
            except re.error:
                pass

    def _extract_domain(self, target: str) -> str:
        target = target.strip().replace("\\", "/")
        if target.startswith(("http://", "https://")):
            return urlparse(target).netloc.split(":")[0].lower()
        if "/" in target:
            target = target.split("/")[0]
        return target.lower()

    async def scan(self, target: str) -> WaybackReport:
        domain = self._extract_domain(target)
        report = WaybackReport(target=domain)

        if not domain or "." not in domain:
            report.errors.append(f"Некорректный домен: {target}")
            return report

        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self.HEADERS,
        ) as session:
            url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=timestamp,original,statuscode"
                f"&collapse=urlkey&limit=5000"
            )
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        report.errors.append(f"archive.org: HTTP {resp.status}")
                        return report
                    try:
                        data = await resp.json(content_type=None)
                    except Exception:
                        report.errors.append("archive.org: некорректный JSON")
                        return report
            except asyncio.TimeoutError:
                report.errors.append("archive.org: таймаут (30 сек)")
                return report
            except Exception as e:
                report.errors.append(f"archive.org: {type(e).__name__}")
                return report

        if not data or len(data) < 2:
            report.errors.append("Снапшотов не найдено — возможно, сайт никогда не индексировался")
            return report

        report.total_snapshots = len(data) - 1
        seen_urls: Set[str] = set()

        for row in data[1:]:
            if len(row) < 3:
                continue
            ts, original, status = row[0], row[1], row[2]
            if original in seen_urls:
                continue
            seen_urls.add(original)

            try:
                status_int = int(status) if status and status != "-" else 0
            except ValueError:
                status_int = 0

            for category, pattern in SUSPICIOUS_PATTERNS:
                m = pattern.search(original)
                if m:
                    report.suspicious.append(ArchivedURL(
                        url=original,
                        timestamp=self._format_ts(ts),
                        status=status_int,
                        category=category,
                        match=m.group(0),
                    ))
                    break

            if self.FLAG_PATTERN:
                for flag in self.FLAG_PATTERN.findall(original):
                    if flag not in report.flags_found:
                        report.flags_found.append(flag)

        report.unique_urls = len(seen_urls)
        report.suspicious.sort(key=lambda u: (u.category, u.url))
        return report

    @staticmethod
    def _format_ts(ts: str) -> str:
        if len(ts) >= 8:
            return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        return ts