import asyncio
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import urlparse

try:
    import dns.resolver
    import dns.rdatatype
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


@dataclass
class DNSRecord:
    rtype: str
    value: str
    ttl: int = 0


@dataclass
class DNSReport:
    target: str
    records: List[DNSRecord] = field(default_factory=list)
    flags_found: List[str] = field(default_factory=list)
    takeover_candidates: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


TAKEOVER_SIGNATURES = {
    "github.io": "GitHub Pages (возможный takeover, если repo не существует)",
    "herokuapp.com": "Heroku (takeover если app не существует)",
    "amazonaws.com": "AWS S3/CloudFront",
    "azurewebsites.net": "Azure (takeover если app удалена)",
    "cloudapp.net": "Azure CloudApp",
    "cloudfront.net": "CloudFront (dangling CNAME)",
    "bitbucket.io": "Bitbucket Pages",
    "ghost.io": "Ghost (takeover если blog удалён)",
    "pantheon.io": "Pantheon",
    "shopify.com": "Shopify",
    "tumblr.com": "Tumblr",
    "wordpress.com": "WordPress.com",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "helpscoutdocs.com": "HelpScout",
    "readme.io": "ReadMe.io",
    "surge.sh": "Surge.sh",
    "netlify.com": "Netlify",
    "trafficmanager.net": "Azure Traffic Manager",
}


class DNSRecon:
    RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV"]

    def __init__(self, timeout: float = 5.0, flag_prefix: str = ""):
        self.timeout = timeout
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

    async def scan(self, target: str) -> DNSReport:
        domain = self._extract_domain(target)
        report = DNSReport(target=domain)

        if not DNS_AVAILABLE:
            report.errors.append("dnspython не установлен. Выполни: pip install dnspython")
            return report

        if not domain or "." not in domain:
            report.errors.append(f"Некорректный домен: {target}")
            return report

        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(None, self._query, domain, rtype, report)
            for rtype in self.RECORD_TYPES
        ]
        # Дополнительные специфичные запросы
        tasks.append(loop.run_in_executor(None, self._query, f"_dmarc.{domain}", "TXT", report))
        tasks.append(loop.run_in_executor(None, self._query, f"default._domainkey.{domain}", "TXT", report))

        await asyncio.gather(*tasks, return_exceptions=True)

        self._check_takeover(report)
        self._search_flags(report)
        report.records.sort(key=lambda r: (self.RECORD_TYPES.index(r.rtype) if r.rtype in self.RECORD_TYPES else 99, r.value))
        return report

    def _query(self, domain: str, rtype: str, report: DNSReport):
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                value = str(rdata).strip('"')
                report.records.append(DNSRecord(rtype=rtype, value=value, ttl=int(answers.rrset.ttl)))
        except dns.resolver.NXDOMAIN:
            if rtype == "A":
                report.errors.append(f"NXDOMAIN: домен {domain} не существует")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NoNameservers:
            report.errors.append(f"{rtype}: нет доступных nameserver'ов")
        except dns.exception.Timeout:
            report.errors.append(f"{rtype}: таймаут запроса")
        except Exception as e:
            if "NXDOMAIN" not in str(e) and "NoAnswer" not in str(e):
                report.errors.append(f"{rtype}: {type(e).__name__}")

    def _check_takeover(self, report: DNSReport):
        for rec in report.records:
            if rec.rtype != "CNAME":
                continue
            target = rec.value.rstrip(".")
            for sig, desc in TAKEOVER_SIGNATURES.items():
                if target.endswith(sig):
                    report.takeover_candidates.append({
                        "source": report.target,
                        "cname": target,
                        "provider": desc,
                    })
                    break

    def _search_flags(self, report: DNSReport):
        if not self.FLAG_PATTERN:
            return
        for rec in report.records:
            if rec.rtype != "TXT":
                continue
            for flag in self.FLAG_PATTERN.findall(rec.value):
                if flag not in report.flags_found:
                    report.flags_found.append(flag)