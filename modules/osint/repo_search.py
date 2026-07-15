import asyncio
import base64
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import quote

import aiohttp


SENSITIVE_PATTERNS = [
    (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w\-]{16,}", "API Key"),
    (r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^\s'\"]{4,}['\"]", "Password/Secret"),
    (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{16,}", "AWS credentials"),
    (r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\sKEY-----", "Private key"),
    (r"(?i)(mysql|postgres|mongodb)://\w+:[^\s@]+@[^\s]+", "DB connection string"),
    (r"(?i)ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"(?i)gho_[A-Za-z0-9]{36}", "GitHub OAuth token"),
    (r"(?i)sk-[A-Za-z0-9]{32,}", "OpenAI API key"),
    (r"(?i)xox[baprs]-[A-Za-z0-9\-]+", "Slack token"),
    (r"(?i)eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "JWT token"),
]

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production",
    "config.json", "config.yaml", "config.yml", "settings.py",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".htpasswd", "shadow", "passwd",
    "credentials", "secrets.json", "wp-config.php",
    ".npmrc", ".pypirc", "netrc",
]


@dataclass
class Finding:
    repo: str
    path: str
    category: str
    content: str
    url: str = ""


@dataclass
class RepoInfo:
    name: str
    full_name: str
    url: str
    description: str = ""
    default_branch: str = "main"
    size: int = 0
    private: bool = False
    language: str = ""
    updated_at: str = ""


@dataclass
class RepoReport:
    username: str
    repos: List[RepoInfo] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    flags_found: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class RepoSearch:
    HEADERS = {
        "User-Agent": "DarkRecon/1.0 (CTF-AutoTool)",
        "Accept": "application/vnd.github+json",
    }

    def __init__(
        self,
        github_token: Optional[str] = None,
        timeout: float = 10.0,
        flag_prefix: str = "",
    ):
        self.github_token = github_token
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.flag_prefix = flag_prefix.strip()
        self.FLAG_PATTERN = None
        if self.flag_prefix:
            try:
                self.FLAG_PATTERN = re.compile(rf"{re.escape(self.flag_prefix)}\{{[^}}]+\}}")
            except re.error:
                pass

    def _headers(self) -> Dict:
        h = dict(self.HEADERS)
        if self.github_token:
            h["Authorization"] = f"token {self.github_token}"
        return h

    async def scan_github(self, username: str) -> RepoReport:
        report = RepoReport(username=username)
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self._headers(),
        ) as session:
            repos = await self._fetch_repos(session, username, report)
            report.repos = repos
            if repos:
                tasks = [self._scan_repo(session, r, report) for r in repos[:20]]
                await asyncio.gather(*tasks, return_exceptions=True)
        return report

    async def _fetch_repos(self, session: aiohttp.ClientSession, username: str, report: RepoReport) -> List[RepoInfo]:
        url = f"https://api.github.com/users/{quote(username)}/repos?per_page=100&sort=updated"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    report.errors.append(f"GitHub API: {resp.status} (возможно, rate limit или пользователь не найден)")
                    return []
                data = await resp.json()
                repos = []
                for r in data:
                    repos.append(RepoInfo(
                        name=r.get("name", ""),
                        full_name=r.get("full_name", ""),
                        url=r.get("html_url", ""),
                        description=(r.get("description") or "")[:80],
                        default_branch=r.get("default_branch", "main"),
                        size=r.get("size", 0),
                        private=r.get("private", False),
                        language=r.get("language") or "",
                        updated_at=r.get("updated_at", ""),
                    ))
                return repos
        except Exception as e:
            report.errors.append(f"Ошибка получения репозиториев: {e}")
            return []

    async def _scan_repo(self, session: aiohttp.ClientSession, repo: RepoInfo, report: RepoReport):
        tree_url = f"https://api.github.com/repos/{repo.full_name}/git/trees/{repo.default_branch}?recursive=1"
        try:
            async with session.get(tree_url) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
                tree = data.get("tree", [])

                sensitive_paths = []
                for item in tree:
                    if item.get("type") != "blob":
                        continue
                    path = item.get("path", "")
                    if self._is_sensitive_file(path):
                        sensitive_paths.append(path)
                    for pattern, category in SENSITIVE_PATTERNS:
                        if re.search(pattern, path, re.IGNORECASE):
                            sensitive_paths.append(path)
                            break

                for path in sensitive_paths[:10]:
                    await self._fetch_file(session, repo, path, report)

                if self.FLAG_PATTERN:
                    await self._search_flag_in_tree(session, repo, tree, report)
        except Exception:
            return

    def _is_sensitive_file(self, path: str) -> bool:
        name = path.split("/")[-1].lower()
        for pattern in SENSITIVE_FILES:
            if name == pattern.lower() or path.endswith(pattern):
                return True
        return False

    async def _fetch_file(self, session: aiohttp.ClientSession, repo: RepoInfo, path: str, report: RepoReport):
        url = f"https://api.github.com/repos/{repo.full_name}/contents/{quote(path)}"
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
                if data.get("encoding") != "base64":
                    return
                content_b64 = data.get("content", "")
                try:
                    content = base64.b64decode(content_b64).decode("utf-8", errors="ignore")
                except Exception:
                    return

                for pattern, category in SENSITIVE_PATTERNS:
                    for match in re.finditer(pattern, content):
                        snippet = match.group(0)
                        finding = Finding(
                            repo=repo.full_name,
                            path=path,
                            category=category,
                            content=snippet[:100],
                            url=f"{repo.url}/blob/{repo.default_branch}/{path}",
                        )
                        if not any(f.content == snippet[:100] and f.path == path for f in report.findings):
                            report.findings.append(finding)
        except Exception:
            return

    async def _search_flag_in_tree(self, session: aiohttp.ClientSession, repo: RepoInfo, tree: List[Dict], report: RepoReport):
        text_files = [
            item for item in tree
            if item.get("type") == "blob"
            and item.get("size", 0) < 100_000
            and self._looks_like_text(item.get("path", ""))
        ][:30]

        for item in text_files:
            path = item.get("path", "")
            url = f"https://api.github.com/repos/{repo.full_name}/contents/{quote(path)}"
            try:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.json()
                    if data.get("encoding") != "base64":
                        continue
                    content = base64.b64decode(data.get("content", "")).decode("utf-8", errors="ignore")
                    flags = self.FLAG_PATTERN.findall(content)
                    for flag in flags:
                        if flag not in report.flags_found:
                            report.flags_found.append(flag)
                            report.findings.append(Finding(
                                repo=repo.full_name,
                                path=path,
                                category="FLAG",
                                content=flag,
                                url=f"{repo.url}/blob/{repo.default_branch}/{path}",
                            ))
            except Exception:
                continue

    def _looks_like_text(self, path: str) -> bool:
        text_exts = (".md", ".txt", ".json", ".yml", ".yaml", ".xml", ".html",
                     ".js", ".ts", ".py", ".sh", ".rb", ".go", ".java", ".c",
                     ".cpp", ".h", ".cfg", ".conf", ".ini", ".toml", ".rst")
        return any(path.lower().endswith(ext) for ext in text_exts)