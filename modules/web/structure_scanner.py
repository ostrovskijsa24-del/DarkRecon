import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import urlparse
from xml.etree import ElementTree

import aiofiles
import aiohttp


DEFAULT_WORDLIST = [
    "admin", "login", "api", "backup", "dev", "test", "secret", "config",
    ".git", ".git/HEAD", ".git/config", ".svn", ".env", ".htaccess",
    "flag", "flag.txt", "flag.php", "robots.txt", "sitemap.xml",
    "uploads", "files", "static", "media", "assets", "css", "js", "images", "img",
    "docs", "doc", "documentation", "api/v1", "api/v2", "v1", "v2",
    "admin.php", "login.php", "wp-admin", "wp-login.php", "phpmyadmin",
    "console", "debug", "monitor", "health", "status", "info", "version",
    "metrics", "swagger", "graphql", ".well-known", "security.txt",
    "ads.txt", "humans.txt", "error", "old", "new", "archive", "temp", "tmp",
    "shell", "cmd", "exec", "source", "src", "include", "lib",
    "backup.sql", "dump.sql", "db.sql", "database.sql",
    "readme", "README.md", "README.txt", "CHANGELOG.md", "LICENSE",
    "server-status", "server-info",
]


@dataclass
class ScanResult:
    url: str
    status: int
    size: int
    content_type: str = ""
    redirect: str = ""


@dataclass
class StructureReport:
    target: str
    robots_paths: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    fuzz_hits: List[ScanResult] = field(default_factory=list)


class StructureScanner:
    COMMON_HEADERS = {
        "User-Agent": "DarkRecon/1.0 (CTF-AutoTool)",
        "Accept": "*/*",
    }

    def __init__(
        self,
        target_url: str,
        concurrency: int = 30,
        timeout: float = 8.0,
        interesting_statuses: Tuple[int, ...] = (200, 301, 302, 401, 403, 405, 500),
    ):
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = "http://" + target_url
        self.target = target_url.rstrip("/")
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.interesting_statuses = interesting_statuses
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(concurrency)

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        self._session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self.COMMON_HEADERS,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _fetch(self, url: str, *, allow_redirects: bool = True) -> Optional[aiohttp.ClientResponse]:
        try:
            async with self._semaphore:
                return await self._session.get(url, allow_redirects=allow_redirects)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None

    async def parse_robots_txt(self) -> List[str]:
        resp = await self._fetch(f"{self.target}/robots.txt")
        if not resp or resp.status != 200:
            return []
        text = await resp.text(errors="ignore")
        paths = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for directive in ("Disallow:", "Allow:", "disallow:", "allow:"):
                if line.startswith(directive):
                    path = line[len(directive):].strip()
                    if path and path not in paths:
                        paths.append(path)
        return paths

    async def parse_sitemap_xml(self) -> List[str]:
        resp = await self._fetch(f"{self.target}/sitemap.xml")
        if not resp or resp.status != 200:
            return []
        text = await resp.text(errors="ignore")
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError:
            return []
        ns = "http://www.sitemaps.org/schemas/sitemap/0.9"
        urls = [loc.text.strip() for loc in root.findall(f".//{{{ns}}}loc") if loc.text]
        for sitemap_loc in root.findall(f".//{{{ns}}}sitemap/{{{ns}}}loc"):
            if sitemap_loc.text:
                nested_resp = await self._fetch(sitemap_loc.text.strip())
                if nested_resp and nested_resp.status == 200:
                    try:
                        nested_root = ElementTree.fromstring(await nested_resp.text(errors="ignore"))
                        urls.extend(loc.text.strip() for loc in nested_root.findall(f".//{{{ns}}}loc") if loc.text)
                    except ElementTree.ParseError:
                        pass
        return urls

    async def load_wordlist(self, wordlist_path: Optional[str]) -> List[str]:
        if not wordlist_path:
            return DEFAULT_WORDLIST.copy()
        async with aiofiles.open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = await f.readlines()
        return [w.strip() for w in lines if w.strip() and not w.startswith("#")]

    async def _probe_path(self, path: str) -> Optional[ScanResult]:
        url = self.target + (path if path.startswith("/") else "/" + path)
        resp = await self._fetch(url, allow_redirects=False)
        if not resp or resp.status not in self.interesting_statuses:
            return None
        try:
            size = len(await resp.read())
        except Exception:
            size = 0
        redirect = resp.headers.get("Location", "") if resp.status in (301, 302, 307, 308) else ""
        return ScanResult(
            url=url,
            status=resp.status,
            size=size,
            content_type=resp.headers.get("Content-Type", "").split(";")[0],
            redirect=redirect,
        )

    async def fuzz_directories(self, wordlist: List[str]) -> List[ScanResult]:
        tasks = [asyncio.create_task(self._probe_path(e)) for e in wordlist]
        hits = [h for h in await asyncio.gather(*tasks) if h]
        hits.sort(key=lambda r: (r.status, r.url))
        return hits

    async def run(self, wordlist_path: Optional[str] = None) -> StructureReport:
        report = StructureReport(target=self.target)
        wordlist = await self.load_wordlist(wordlist_path)
        robots_task = asyncio.create_task(self.parse_robots_txt())
        sitemap_task = asyncio.create_task(self.parse_sitemap_xml())
        fuzz_task = asyncio.create_task(self.fuzz_directories(wordlist))
        report.robots_paths = await robots_task
        report.sitemap_urls = await sitemap_task
        report.fuzz_hits = await fuzz_task
        return report