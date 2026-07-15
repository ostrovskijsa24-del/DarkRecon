import asyncio
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup, Comment


@dataclass
class SecurityHeaders:
    present: Dict[str, str] = field(default_factory=dict)
    missing: List[str] = field(default_factory=list)
    misconfig: List[str] = field(default_factory=list)


@dataclass
class SoftwareReveal:
    name: str
    version: str = ""
    header: str = ""


@dataclass
class HiddenField:
    name: str
    value: str
    form_action: str = ""


@dataclass
class ResponseReport:
    url: str
    status: int
    final_url: str = ""
    security_headers: SecurityHeaders = field(default_factory=SecurityHeaders)
    software: List[SoftwareReveal] = field(default_factory=list)
    cookies_info: List[Dict] = field(default_factory=list)
    hidden_fields: List[HiddenField] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    internal_links: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    flags_found: List[str] = field(default_factory=list)


REQUIRED_HEADERS = {
    "Strict-Transport-Security": "Отсутствует HSTS — возможен MITM через downgrade до HTTP",
    "X-Frame-Options": "Нет защиты от clickjacking (X-Frame-Options)",
    "X-Content-Type-Options": "Отсутствует X-Content-Type-Options — возможен MIME-sniffing",
    "Content-Security-Policy": "Нет CSP — риск XSS и инъекций",
    "Referrer-Policy": "Не настроен Referrer-Policy — возможна утечка URL",
    "Permissions-Policy": "Не настроен Permissions-Policy",
    "Cross-Origin-Opener-Policy": "Отсутствует COOP",
    "Cross-Origin-Resource-Policy": "Отсутствует CORP",
}

SOFTWARE_HEADERS = {
    "Server": "Web-сервер",
    "X-Powered-By": "Backend/фреймворк",
    "X-AspNet-Version": "ASP.NET",
    "X-AspNetMvc-Version": "ASP.NET MVC",
    "X-Generator": "Генератор/CMF",
    "X-Drupal-Cache": "Drupal",
    "X-Pingback": "WordPress/CMS",
    "X-Version": "Версия",
    "X-Runtime": "Framework",
    "Via": "Прокси/CDN",
    "X-Cache": "CDN",
}


class ResponseAnalyzer:
    COMMON_HEADERS = {
        "User-Agent": "DarkRecon/1.0 (CTF-AutoTool)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    def __init__(self, target_url: str, timeout: float = 10.0, flag_prefix: str = ""):
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = "http://" + target_url
        self.target = target_url.rstrip("/")
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.base_domain = urlparse(self.target).netloc
        self.FLAG_PATTERN = self._build_flag_pattern(flag_prefix.strip())

    @staticmethod
    def _build_flag_pattern(prefix: str) -> Optional[re.Pattern]:
        if not prefix:
            return None
        if "{" in prefix or r"\{" in prefix:
            try:
                return re.compile(prefix)
            except re.error:
                return None
        try:
            return re.compile(rf"{re.escape(prefix)}\{{[^}}]+\}}")
        except re.error:
            return None

    async def analyze(self, urls: Optional[List[str]] = None) -> List[ResponseReport]:
        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self.COMMON_HEADERS,
        ) as session:
            targets = urls if urls else [self.target]
            tasks = [self._analyze_url(session, u) for u in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            reports = []
            for r in results:
                if isinstance(r, ResponseReport):
                    reports.append(r)
                elif isinstance(r, Exception):
                    reports.append(ResponseReport(url=str(r), status=0, errors=[str(r)]))
            return reports

    async def _analyze_url(self, session: aiohttp.ClientSession, url: str) -> ResponseReport:
        try:
            async with session.get(url, allow_redirects=True) as resp:
                status = resp.status
                final_url = str(resp.url)
                headers = dict(resp.headers)
                body = ""
                content_type = resp.headers.get("Content-Type", "")
                if "text/html" in content_type or "application/xhtml" in content_type:
                    body = await resp.text(errors="ignore")
                cookies_info = self._analyze_cookies(resp)
        except Exception as e:
            return ResponseReport(url=url, status=0, errors=[f"Request failed: {e}"])

        report = ResponseReport(url=url, status=status, final_url=final_url)
        report.cookies_info = cookies_info
        report.security_headers = self._check_security_headers(headers)
        report.software = self._detect_software(headers)

        if body:
            self._parse_html(body, final_url, report)

        return report

    def _check_security_headers(self, headers: Dict[str, str]) -> SecurityHeaders:
        present = {}
        missing = []
        misconfig = []
        lower = {k.lower(): (k, v) for k, v in headers.items()}

        for header, description in REQUIRED_HEADERS.items():
            if header.lower() in lower:
                actual_key, value = lower[header.lower()]
                present[actual_key] = value
            else:
                missing.append(f"{header} — {description}")

        if "x-frame-options" in lower:
            v = lower["x-frame-options"][1].upper()
            if v not in ("DENY", "SAMEORIGIN") and not v.startswith("ALLOW-FROM"):
                misconfig.append(f"X-Frame-Options = {v} (не DENY/SAMEORIGIN)")

        if "x-content-type-options" in lower:
            v = lower["x-content-type-options"][1].lower()
            if v != "nosniff":
                misconfig.append(f"X-Content-Type-Options = {v} (должен быть nosniff)")

        if "strict-transport-security" in lower:
            v = lower["strict-transport-security"][1]
            if "max-age=0" in v.lower():
                misconfig.append(f"HSTS max-age=0 — отключено")

        if "content-security-policy" in lower:
            v = lower["content-security-policy"][1].lower()
            if "'unsafe-inline'" in v or "'unsafe-eval'" in v:
                misconfig.append(f"CSP содержит unsafe-inline/unsafe-eval")

        return SecurityHeaders(present=present, missing=missing, misconfig=misconfig)

    def _detect_software(self, headers: Dict[str, str]) -> List[SoftwareReveal]:
        found = []
        for header, description in SOFTWARE_HEADERS.items():
            if header in headers:
                found.append(SoftwareReveal(name=description, version=headers[header], header=header))
        return found

    def _analyze_cookies(self, resp: aiohttp.ClientResponse) -> List[Dict]:
        cookies = []
        for name, morsel in resp.cookies.items():
            cookies.append({
                "name": name,
                "value": morsel.value,
                "path": morsel.get("path", "/"),
                "secure": morsel.get("secure", False),
                "httponly": morsel.get("httponly", False),
                "samesite": morsel.get("samesite", "None"),
            })
        return cookies

    def _parse_html(self, body: str, current_url: str, report: ResponseReport):
        soup = BeautifulSoup(body, "html.parser")

        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = comment.strip()
            if text and len(text) > 3:
                report.comments.append(text)

        for inp in soup.find_all("input", attrs={"type": "hidden"}):
            name = inp.get("name", "") or inp.get("id", "")
            value = inp.get("value", "")
            form = inp.find_parent("form")
            action = ""
            if form:
                action = form.get("action", "")
                if action:
                    action = urljoin(current_url, action)
            report.hidden_fields.append(HiddenField(name=name, value=value, form_action=action))

        # Поиск флагов во всём теле (комментарии + hidden + plain text)
        if self.FLAG_PATTERN:
            report.flags_found = list(set(self.FLAG_PATTERN.findall(body)))

        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                action = urljoin(current_url, action)
            report.forms.append({
                "method": form.get("method", "GET").upper(),
                "action": action,
                "fields": [
                    {"name": f.get("name"), "type": f.get("type", "text")}
                    for f in form.find_all(("input", "textarea", "select"))
                ],
            })

        seen = set()
        for tag in soup.find_all(["a", "link", "script", "img"]):
            href = tag.get("href") or tag.get("src")
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full = urljoin(current_url, href)
            parsed = urlparse(full)
            if parsed.netloc == self.base_domain and full not in seen:
                seen.add(full)
                report.internal_links.append(full)

        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                full = urljoin(current_url, src)
                report.scripts.append(full)
            elif script.string and len(script.string) > 50:
                report.scripts.append(f"[inline JS: {len(script.string)} chars]")

        error_patterns = [
            r"(?i)warning\s*:",
            r"(?i)fatal error",
            r"(?i)uncaught exception",
            r"(?i)stack trace",
            r"at\s+[\w\.]+\([^\)]+\)\s+line\s+\d+",
        ]
        for pattern in error_patterns:
            for match in re.finditer(pattern, body):
                context = body[max(0, match.start() - 30):match.end() + 30].replace("\n", " ")
                if context not in report.errors:
                    report.errors.append(context)