import asyncio
import socket
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from urllib.parse import urlparse

import aiohttp
import whois


@dataclass
class WhoisData:
    target: str
    registrar: str = ""
    creation_date: str = ""
    expiration_date: str = ""
    updated_date: str = ""
    name_servers: List[str] = field(default_factory=list)
    registrant_name: str = ""
    registrant_org: str = ""
    registrant_country: str = ""
    emails: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    raw_text: str = ""
    error: str = ""


@dataclass
class GeoIPData:
    target: str
    ip: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    postal: str = ""
    isp: str = ""
    org: str = ""
    asn: str = ""
    lat: float = 0.0
    lon: float = 0.0
    timezone: str = ""
    error: str = ""


@dataclass
class WhoisGeoReport:
    target: str
    whois: Optional[WhoisData] = None
    geoip: Optional[GeoIPData] = None


class WhoisGeoIPChecker:
    GEOIP_APIS = [
        "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query",
        "https://ipinfo.io/{ip}/json",
    ]

    HEADERS = {
        "User-Agent": "DarkRecon/1.0 (CTF-AutoTool)",
        "Accept": "application/json",
    }

    def __init__(self, timeout: float = 10.0):
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    def _extract_domain(self, target: str) -> str:
        target = target.strip()
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return parsed.netloc.split(":")[0]
        if "/" in target:
            target = target.split("/")[0]
        return target.lower()

    def _is_ip(self, target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    def _resolve_domain(self, domain: str) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def _format_date(self, dt) -> str:
        if not dt:
            return ""
        if isinstance(dt, list):
            dt = dt[0] if dt else None
        if dt is None:
            return ""
        try:
            return str(dt).split()[0]
        except Exception:
            return str(dt)

    def _extract_emails(self, text: str) -> List[str]:
        if not text:
            return []
        pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails = re.findall(pattern, text)
        filtered = [e for e in emails if not e.lower().endswith(("whois", "@privacy", "@redacted"))]
        return list(set(filtered))[:10]

    def _whois_lookup(self, target: str) -> WhoisData:
        data = WhoisData(target=target)
        try:
            w = whois.whois(target)
            data.registrar = str(w.registrar or "")
            data.creation_date = self._format_date(w.creation_date)
            data.expiration_date = self._format_date(w.expiration_date)
            data.updated_date = self._format_date(w.updated_date)
            
            ns = w.name_servers or []
            if isinstance(ns, str):
                ns = [ns]
            data.name_servers = [str(n).lower() for n in ns]
            
            data.registrant_name = str(w.get("registrant_name", "") or "")
            data.registrant_org = str(w.get("org", "") or w.get("registrant_org", "") or "")
            data.registrant_country = str(w.get("registrant_country", "") or "")
            
            status = w.status or []
            if isinstance(status, str):
                status = [status]
            data.status = status[:5]
            
            emails = w.emails or []
            if isinstance(emails, str):
                emails = [emails]
            data.emails = list(set(emails))[:10]
            
            if hasattr(w, "text") and w.text:
                data.raw_text = str(w.text)[:500]
                if not data.emails:
                    data.emails = self._extract_emails(data.raw_text)
        except Exception as e:
            data.error = f"{type(e).__name__}: {str(e)[:100]}"
        return data

    async def _geoip_lookup(self, ip: str) -> GeoIPData:
        data = GeoIPData(target=ip, ip=ip)
        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        async with aiohttp.ClientSession(
            timeout=self.timeout,
            connector=connector,
            headers=self.HEADERS,
        ) as session:
            url = self.GEOIP_APIS[0].format(ip=ip)
            try:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        j = await resp.json()
                        if j.get("status") == "success":
                            data.country = j.get("country", "")
                            data.country_code = j.get("countryCode", "")
                            data.region = j.get("regionName", "")
                            data.city = j.get("city", "")
                            data.postal = j.get("zip", "")
                            data.isp = j.get("isp", "")
                            data.org = j.get("org", "")
                            data.asn = j.get("as", "")
                            data.lat = j.get("lat", 0.0)
                            data.lon = j.get("lon", 0.0)
                            data.timezone = j.get("timezone", "")
                            return data
            except Exception as e:
                data.error = f"API 1: {type(e).__name__}"

            try:
                url2 = self.GEOIP_APIS[1].format(ip=ip)
                async with session.get(url2) as resp:
                    if resp.status == 200:
                        j = await resp.json()
                        data.country = j.get("country", "")
                        data.country_code = j.get("country", "")
                        data.region = j.get("region", "")
                        data.city = j.get("city", "")
                        data.postal = j.get("postal", "")
                        data.org = j.get("org", "")
                        loc = j.get("loc", "")
                        if "," in loc:
                            try:
                                data.lat, data.lon = map(float, loc.split(","))
                            except ValueError:
                                pass
                        data.timezone = j.get("timezone", "")
                        return data
            except Exception as e:
                data.error = f"API 2: {type(e).__name__}"
        return data

    async def check(self, target: str) -> WhoisGeoReport:
        target = target.strip()
        if not target:
            return WhoisGeoReport(target="")

        domain = self._extract_domain(target)
        is_ip = self._is_ip(domain)

        report = WhoisGeoReport(target=domain)

        if is_ip:
            ip = domain
        else:
            loop = asyncio.get_event_loop()
            whois_data = await loop.run_in_executor(None, self._whois_lookup, domain)
            report.whois = whois_data
            ip = self._resolve_domain(domain)
            if not ip:
                report.geoip = GeoIPData(target=domain, error="DNS-резолвинг не удался")
                return report

        report.geoip = await self._geoip_lookup(ip)
        return report