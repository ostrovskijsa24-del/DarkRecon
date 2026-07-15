import asyncio
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import quote

import aiohttp


@dataclass
class PlatformResult:
    platform: str
    exists: bool
    url: str
    status: int = 0
    extra: str = ""


@dataclass
class UsernameReport:
    username: str
    results: List[PlatformResult] = field(default_factory=list)

    @property
    def found_count(self) -> int:
        return sum(1 for r in self.results if r.exists)


PLATFORMS = [
    {
        "name": "GitHub",
        "url": "https://github.com/{username}",
        "api": "https://api.github.com/users/{username}",
        "error_indicators": [404],
        "check_type": "status",
    },
    {
        "name": "GitLab",
        "url": "https://gitlab.com/{username}",
        "api": "https://gitlab.com/api/v4/users?username={username}",
        "error_indicators": [404, "[]"],
        "check_type": "json_array",
    },
    {
        "name": "Docker Hub",
        "url": "https://hub.docker.com/u/{username}",
        "api": "https://hub.docker.com/v2/users/{username}/",
        "error_indicators": [404],
        "check_type": "status",
    },
    {
        "name": "Kaggle",
        "url": "https://www.kaggle.com/{username}",
        "api": None,
        "error_indicators": [404],
        "check_type": "status",
    },
    {
        "name": "HackTheBox",
        "url": "https://app.hackthebox.com/profile/{username}",
        "api": None,
        "error_indicators": [404],
        "check_type": "status",
    },
    {
        "name": "TryHackMe",
        "url": "https://tryhackme.com/p/{username}",
        "api": None,
        "error_indicators": [404],
        "check_type": "status",
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com/user/{username}",
        "api": "https://www.reddit.com/user/{username}/about.json",
        "error_indicators": [404],
        "check_type": "status",
    },
    {
        "name": "Twitter/X",
        "url": "https://x.com/{username}",
        "api": None,
        "error_indicators": [404, "This account doesn"],
        "check_type": "text_or_status",
    },
    {
        "name": "Telegram",
        "url": "https://t.me/{username}",
        "api": None,
        "error_indicators": ["If you have <strong>Telegram</strong>"],
        "check_type": "text",
    },
    {
        "name": "Steam",
        "url": "https://steamcommunity.com/id/{username}",
        "api": None,
        "error_indicators": ["The specified profile could not be found"],
        "check_type": "text",
    },
]


class UsernameRecon:
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 DarkRecon/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    def __init__(self, timeout: float = 10.0, concurrency: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.concurrency = concurrency

    async def scan(self, username: str) -> UsernameReport:
        report = UsernameReport(username=username)
        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self.HEADERS,
        ) as session:
            tasks = [self._check_platform(session, username, p) for p in PLATFORMS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, PlatformResult):
                    report.results.append(r)
        report.results.sort(key=lambda x: (not x.exists, x.platform))
        return report

    async def _check_platform(self, session: aiohttp.ClientSession, username: str, platform: Dict) -> PlatformResult:
        url = platform["url"].format(username=quote(username))
        api = platform["api"].format(username=quote(username)) if platform["api"] else None
        target = api or url

        try:
            async with session.get(target, allow_redirects=True) as resp:
                status = resp.status
                body = ""
                if platform["check_type"] in ("text", "text_or_status"):
                    body = await resp.text(errors="ignore")
                elif platform["check_type"] == "json_array":
                    body = await resp.text(errors="ignore")

                exists = self._evaluate(platform, status, body, username)
                extra = ""
                if exists and platform["name"] == "GitHub" and status == 200:
                    extra = await self._github_extra(session, username)
                return PlatformResult(
                    platform=platform["name"],
                    exists=exists,
                    url=url,
                    status=status,
                    extra=extra,
                )
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            return PlatformResult(
                platform=platform["name"],
                exists=False,
                url=url,
                extra=f"Ошибка: {type(e).__name__}",
            )

    def _evaluate(self, platform: Dict, status: int, body: str, username: str) -> bool:
        indicators = platform["error_indicators"]
        ctype = platform["check_type"]

        if ctype == "status":
            return status not in indicators and status < 400
        if ctype == "json_array":
            if status in indicators:
                return False
            return body.strip() not in indicators and "[]" not in body[:10]
        if ctype == "text":
            for ind in indicators:
                if ind in body:
                    return False
            return True
        if ctype == "text_or_status":
            if status in indicators:
                return False
            for ind in indicators:
                if isinstance(ind, str) and ind in body:
                    return False
            return True
        return False

    async def _github_extra(self, session: aiohttp.ClientSession, username: str) -> str:
        try:
            async with session.get(f"https://api.github.com/users/{quote(username)}") as resp:
                if resp.status != 200:
                    return ""
                data = await resp.json()
                parts = []
                if data.get("name"):
                    parts.append(f"name: {data['name']}")
                if data.get("email"):
                    parts.append(f"email: {data['email']}")
                if data.get("bio"):
                    parts.append(f"bio: {data['bio'][:60]}")
                if data.get("public_repos"):
                    parts.append(f"repos: {data['public_repos']}")
                if data.get("blog"):
                    parts.append(f"blog: {data['blog']}")
                return " | ".join(parts)
        except Exception:
            return ""