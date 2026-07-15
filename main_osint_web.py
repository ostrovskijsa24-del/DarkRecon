import asyncio
import json
import sys
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm

from modules.web.structure_scanner import StructureScanner
from modules.web.response_analyzer import ResponseAnalyzer
from modules.web.cookie_analyzer import CookieAnalyzer
from modules.web.jwt_tool import JWTTool
from modules.web.cors_scanner import CORSScanner
from modules.osint.username_recon import UsernameRecon
from modules.osint.repo_search import RepoSearch
from modules.osint.whois_geoip import WhoisGeoIPChecker
from modules.web.subdomain_enum import SubdomainEnumerator
from modules.web.dns_recon import DNSRecon
from modules.web.wayback_analyzer import WaybackAnalyzer


console = Console()


def main_menu():
    console.print("\n[bold magenta]╔═══ DARKRECON ═══╗[/]")
    console.print("[yellow]1[/] 🌐 Web-безопасность")
    console.print("[yellow]2[/] 🔎 OSINT")
    console.print("[yellow]0[/] ❌ Выход")
    return IntPrompt.ask(">>>", choices=["0", "1", "2"])


def web_menu():
    console.print("\n[bold cyan]═══ WEB-БЕЗОПАСНОСТЬ ═══[/]")
    console.print("[green]1[/] Сканер структуры       [dim](robots.txt, sitemap.xml, фаззинг)[/]")
    console.print("[green]2[/] Анализатор ответов     [dim](HTTP-заголовки, HTML, скрытые поля)[/]")
    console.print("[green]3[/] Анализатор Cookie      [dim](декод Base64/Hex/JWT, поиск флагов)[/]")
    console.print("[green]4[/] JWT-инструмент         [dim](декод, alg:none, брутфорс секрета)[/]")
    console.print("[green]5[/] CORS-сканер            [dim](8 векторов misconfiguration)[/]")
    console.print("[green]6[/] Поддомены              [dim](crt.sh + HackerTarget + AlienVault)[/]")
    console.print("[green]7[/] Анализ DNS             [dim](все типы записей + флаги в TXT)[/]")
    console.print("[green]8[/] История сайта          [dim](история сайта через archive.org)[/]")
    console.print("[yellow]0[/] Назад")
    return IntPrompt.ask(">>>", choices=["0", "1", "2", "3", "4", "5", "6", "7", "8"])


def osint_menu():
    console.print("\n[bold cyan]═══ OSINT ═══[/]")
    console.print("[green]1[/] Проверка идентификаторов  [dim](GitHub, GitLab, Docker Hub, HTB, THM)[/]")
    console.print("[green]2[/] Поиск репозиториев        [dim](анализ GitHub на утечки и флаги)[/]")
    console.print("[green]3[/] WHOIS & GeoIP             [dim](регистрационные данные и геолокация)[/]")
    console.print("[yellow]0[/] Назад")
    return IntPrompt.ask(">>>", choices=["0", "1", "2", "3", "4"])


# ═══════════════ Вывод отчётов ═══════════════

def print_report(report):
    console.print(f"\n[bold cyan]Цель:[/] {report.target}")
    if report.robots_paths:
        console.print(f"[yellow]robots.txt:[/] найдено {len(report.robots_paths)} путей")
        if len(report.robots_paths) > 20:
            show_all = Confirm.ask(f"[dim]Показать все {len(report.robots_paths)} путей?[/]", default=False)
            if show_all:
                for p in report.robots_paths:
                    console.print(f"  • {p}")
            else:
                console.print("[dim]Показаны первые 20:[/]")
                for p in report.robots_paths[:20]:
                    console.print(f"  • {p}")
        else:
            for p in report.robots_paths:
                console.print(f"  • {p}")
    if report.sitemap_urls:
        console.print(f"[green]sitemap.xml:[/] найдено {len(report.sitemap_urls)} URL")
        if len(report.sitemap_urls) > 20:
            console.print("[dim]Показаны первые 20:[/]")
            for u in report.sitemap_urls[:20]:
                console.print(f"  • {u}")
        else:
            for u in report.sitemap_urls:
                console.print(f"  • {u}")
    if report.fuzz_hits:
        console.print(f"[bold]Результаты фаззинга:[/] {len(report.fuzz_hits)}")
        for r in report.fuzz_hits:
            console.print(f"  [{r.status}] {r.url}")


def print_response_report(report):
    console.print(f"\n[bold cyan]Цель:[/] {report.url} [статус: {report.status}]")
    if report.flags_found:
        console.print("[bold red]🚩 НАЙДЕНЫ ФЛАГИ:[/]")
        for flag in set(report.flags_found):
            console.print(f"  [green]{flag}[/]")
    if report.software:
        console.print("[yellow]Обнаруженное ПО:[/]")
        for s in report.software:
            console.print(f"  {s.header}: {s.version}")
    if report.comments:
        console.print(f"[yellow]HTML-комментарии:[/] найдено {len(report.comments)}")
        for c in report.comments[:5]:
            console.print(f"  • {c[:100]}")
    if report.hidden_fields:
        console.print(f"[yellow]Скрытые поля форм:[/] найдено {len(report.hidden_fields)}")
        for h in report.hidden_fields[:5]:
            console.print(f"  • {h.name} = {h.value[:50]}")


def print_cookie_analysis(analysis):
    console.print(f"\n[bold cyan]{analysis.name}[/] (тип: {analysis.detected_type})")
    console.print(f"  Исходное: [dim]{analysis.raw_value}[/]")
    decoded_shown = False
    for attempt in analysis.decode_attempts:
        if attempt.success:
            console.print(f"  [green]✓ Декодировано ({attempt.method}):[/] [bold]{attempt.decoded_value}[/]")
            decoded_shown = True
            break
    if not decoded_shown and analysis.detected_type not in ("JWT", "empty", "unknown/plain"):
        console.print(f"  [yellow]⚠ Не удалось декодировать в читаемый текст (бинарные данные/хеш)[/]")
    if analysis.json_data:
        console.print(f"  [yellow]JSON:[/] {json.dumps(analysis.json_data, ensure_ascii=False)}")
    if analysis.jwt_data:
        console.print(f"  [yellow]JWT Header:[/] {json.dumps(analysis.jwt_data.get('header', {}))}")
        if 'payload' in analysis.jwt_data:
            console.print(f"  [yellow]JWT Payload:[/] {json.dumps(analysis.jwt_data['payload'], ensure_ascii=False, indent=2)}")
    if analysis.flags_found:
        console.print("  [bold red]🚩 НАЙДЕНЫ ФЛАГИ:[/]")
        for flag in set(analysis.flags_found):
            console.print(f"    [bold green]{flag}[/]")
    if analysis.suspicious_patterns:
        console.print("  [yellow]⚠ Подозрительные паттерны:[/]")
        for p in set(analysis.suspicious_patterns):
            console.print(f"    • {p}")


def print_jwt_analysis(analysis):
    console.print(f"\n[bold cyan]Анализ JWT[/]")
    if analysis.header:
        console.print(f"  Заголовок: {json.dumps(analysis.header)}")
    if analysis.payload:
        console.print(f"  Payload: {json.dumps(analysis.payload, indent=2)}")
    if analysis.secret_found:
        console.print(f"[bold red]🔑 СЕКРЕТНЫЙ КЛЮЧ НАЙДЕН: {analysis.secret_found}[/]")


def print_cors_report(report):
    console.print(f"\n[bold cyan]Цель:[/] {report.target}")
    console.print(f"[bold]Проверок:[/] {len(report.checks)} | [red]Уязвимостей:[/] {report.vulnerable_count}\n")
    sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}
    for c in report.checks:
        status = "[bold red]✗ УЯЗВИМО[/]" if c.vulnerable else "[green]✓ OK[/]"
        sev = f"[{sev_colors.get(c.severity, 'white')}][{c.severity.upper()}][/]"
        console.print(f"{status} {sev} [cyan]{c.name}[/]")
        console.print(f"    Отправлен Origin: [yellow]{c.origin_sent}[/]")
        if c.acao:
            console.print(f"    ACAO: [yellow]{c.acao}[/]  ACAC: {c.acac or '-'}  ACAM: {c.acam or '-'}")
        if c.vulnerable:
            console.print(f"    [dim]→ {c.description}[/]")
        if c.evidence:
            console.print(f"    [dim]{c.evidence}[/]")
        console.print()


def print_username_report(report):
    console.print(f"\n[bold cyan]Никнейм:[/] {report.username}")
    console.print(f"[bold]Найдено профилей:[/] [green]{report.found_count}[/] из {len(report.results)}\n")
    found = [r for r in report.results if r.exists]
    not_found = [r for r in report.results if not r.exists]
    if found:
        console.print("[bold green]✓ Обнаруженные профили:[/]")
        for r in found:
            console.print(f"  [cyan]{r.platform}[/]: {r.url}")
            if r.extra:
                console.print(f"    [dim]{r.extra}[/]")
    if not_found:
        console.print(f"\n[dim]Не найден на: {', '.join(r.platform for r in not_found)}[/]")


def print_repo_report(report):
    console.print(f"\n[bold cyan]Пользователь:[/] {report.username}")
    console.print(f"[bold]Репозиториев:[/] {len(report.repos)} | [yellow]Находок:[/] {len(report.findings)}")
    if report.errors:
        console.print("\n[red]Ошибки:[/]")
        for e in report.errors:
            console.print(f"  • {e}")
    if report.flags_found:
        console.print("\n[bold red]🚩 НАЙДЕНЫ ФЛАГИ:[/]")
        for flag in report.flags_found:
            console.print(f"  [bold green]{flag}[/]")
    if report.repos:
        console.print(f"\n[yellow]Публичные репозитории:[/]")
        for r in report.repos[:15]:
            console.print(f"  • [cyan]{r.name}[/] [dim]({r.language or 'n/a'}, {r.size}KB)[/] {r.url}")
        if len(report.repos) > 15:
            console.print(f"  [dim]...и ещё {len(report.repos) - 15}[/]")
    if report.findings:
        console.print(f"\n[bold red]⚠ Чувствительные данные:[/]")
        for f in report.findings[:30]:
            console.print(f"  [bold red][{f.category}][/] [cyan]{f.repo}[/]/[yellow]{f.path}[/]")
            console.print(f"    [dim]{f.content}[/]")
            console.print(f"    [dim]{f.url}[/]")


def print_whois_report(report):
    console.print(f"\n[bold cyan]Цель:[/] {report.target}")

    if report.whois:
        w = report.whois
        console.print("\n[bold yellow]═══ WHOIS ═══[/]")
        if w.error:
            console.print(f"  [red]Ошибка:[/] {w.error}")
        else:
            if w.registrar:
                console.print(f"  [cyan]Регистратор:[/] {w.registrar}")
            if w.creation_date:
                console.print(f"  [cyan]Дата создания:[/] {w.creation_date}")
            if w.expiration_date:
                console.print(f"  [cyan]Дата истечения:[/] {w.expiration_date}")
            if w.updated_date:
                console.print(f"  [cyan]Обновлён:[/] {w.updated_date}")
            if w.registrant_org:
                console.print(f"  [cyan]Организация:[/] {w.registrant_org}")
            if w.registrant_name:
                console.print(f"  [cyan]Владелец:[/] {w.registrant_name}")
            if w.registrant_country:
                console.print(f"  [cyan]Страна:[/] {w.registrant_country}")
            if w.name_servers:
                console.print(f"  [cyan]NS-серверы:[/]")
                for ns in w.name_servers[:6]:
                    console.print(f"    • {ns}")
            if w.emails:
                console.print(f"  [bold red]📧 Найденные email:[/]")
                for e in w.emails:
                    console.print(f"    • {e}")
            if w.status:
                console.print(f"  [dim]Статусы: {', '.join(w.status[:5])}[/]")

    if report.geoip:
        g = report.geoip
        console.print("\n[bold yellow]═══ GEOIP ═══[/]")
        if g.error:
            console.print(f"  [red]Ошибка:[/] {g.error}")
        else:
            console.print(f"  [cyan]IP:[/] {g.ip}")
            if g.country:
                console.print(f"  [cyan]Страна:[/] {g.country} [{g.country_code}]")
            if g.region or g.city:
                console.print(f"  [cyan]Регион/город:[/] {g.region}, {g.city}")
            if g.postal:
                console.print(f"  [cyan]Почтовый индекс:[/] {g.postal}")
            if g.timezone:
                console.print(f"  [cyan]Часовой пояс:[/] {g.timezone}")
            if g.isp:
                console.print(f"  [cyan]Провайдер:[/] {g.isp}")
            if g.org:
                console.print(f"  [cyan]Организация:[/] {g.org}")
            if g.asn:
                console.print(f"  [cyan]ASN:[/] {g.asn}")
            if g.lat and g.lon:
                console.print(f"  [cyan]Координаты:[/] {g.lat}, {g.lon}")
                console.print(f"  [dim]Google Maps: https://www.google.com/maps?q={g.lat},{g.lon}[/]")

def print_subdomain_report(report):
    console.print(f"\n[bold cyan]Цель:[/] {report.target}")
    console.print(f"[bold]Найдено поддоменов:[/] [green]{report.total}[/] | [cyan]Живых:[/] {report.alive_count}\n")

    if report.errors:
        console.print("[yellow]⚠ Замечания:[/]")
        for e in report.errors:
            console.print(f"  • {e}")
        console.print()

    alive = [r for r in report.results if r.alive]
    dead = [r for r in report.results if not r.alive]

    if alive:
        console.print("[bold green]✓ Доступные поддомены:[/]")
        for r in alive:
            status_str = f"[{r.http_status}]" if r.http_status else "[DNS]"
            ip = f" → {r.resolved_ip}" if r.resolved_ip else ""
            title = f"  [dim]«{r.http_title}»[/]" if r.http_title else ""
            console.print(f"  • {status_str} [cyan]{r.subdomain}[/]{ip}{title}")
            console.print(f"    [dim]источник: {r.source}[/]")
        console.print()

    if dead:
        console.print(f"[dim]Недоступных (только в списках): {len(dead)}[/]")
        for r in dead[:10]:
            console.print(f"  • [dim]{r.subdomain} ({r.source})[/]")
        if len(dead) > 10:
            console.print(f"  [dim]...и ещё {len(dead) - 10}[/]")


def print_dns_report(report):
    console.print(f"\n[bold cyan]Цель:[/] {report.target}")
    console.print(f"[bold]Записей найдено:[/] [green]{len(report.records)}[/]\n")

    if report.errors:
        console.print("[yellow]⚠ Замечания:[/]")
        for e in report.errors:
            console.print(f"  • {e}")
        console.print()

    if report.flags_found:
        console.print("[bold red]🚩 ФЛАГИ В DNS-ЗАПИСЯХ:[/]")
        for flag in report.flags_found:
            console.print(f"  [bold green]{flag}[/]")
        console.print()

    if report.takeover_candidates:
        console.print("[bold red]⚠ ВОЗМОЖНЫЙ SUBDOMAIN TAKEOVER:[/]")
        for t in report.takeover_candidates:
            console.print(f"  • [cyan]{t['source']}[/] CNAME → [yellow]{t['cname']}[/]")
            console.print(f"    [dim]{t['provider']}[/]")
        console.print()

    if not report.records:
        console.print("[yellow]DNS-записей не найдено[/]")
        return

    grouped = {}
    for r in report.records:
        grouped.setdefault(r.rtype, []).append(r)

    type_order = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "SRV"]
    for rtype in type_order:
        items = grouped.get(rtype, [])
        if not items:
            continue
        console.print(f"[bold cyan]── {rtype} ({len(items)}) ──[/]")
        for item in items:
            console.print(f"  • [yellow]{item.value}[/]  [dim](TTL: {item.ttl})[/]")
        console.print()

    for rtype, items in grouped.items():
        if rtype in type_order:
            continue
        console.print(f"[bold cyan]── {rtype} ({len(items)}) ──[/]")
        for item in items:
            console.print(f"  • [yellow]{item.value}[/]")


def print_wayback_report(report):
    console.print(f"\n[bold cyan]Цель:[/] {report.target}")
    console.print(f"[bold]Снапшотов:[/] {report.total_snapshots} | [bold]Уникальных URL:[/] {report.unique_urls}\n")

    if report.errors:
        console.print("[yellow]⚠ Замечания:[/]")
        for e in report.errors:
            console.print(f"  • {e}")
        console.print()

    if report.flags_found:
        console.print("[bold red]🚩 ФЛАГИ В URL:[/]")
        for flag in report.flags_found:
            console.print(f"  [bold green]{flag}[/]")
        console.print()

    if not report.suspicious:
        console.print("[yellow]Подозрительных URL не найдено[/]")
        return

    console.print(f"[bold red]⚠ Подозрительные URL ({len(report.suspicious)}):[/]\n")

    by_category = {}
    for u in report.suspicious:
        by_category.setdefault(u.category, []).append(u)

    for category, items in by_category.items():
        console.print(f"[bold cyan]── {category} ({len(items)}) ──[/]")
        for item in items[:15]:
            status = f"[{item.status}]" if item.status else "[?]"
            console.print(f"  • {status} [yellow]{item.url}[/]")
            console.print(f"    [dim]дата: {item.timestamp} | совпадение: {item.match}[/]")
            console.print(f"    [dim]https://web.archive.org/web/{item.timestamp.replace('-', '')}/{item.url}[/]")
        if len(items) > 15:
            console.print(f"  [dim]...и ещё {len(items) - 15}[/]")
        console.print()



# ═══════════════ Запуск модулей ═══════════════

async def run_structure():
    console.print("\n[cyan]URL цели[/] (например, http://ctf.example.com):")
    url = Prompt.ask(">>>")
    use_custom = Confirm.ask("Использовать свой словарь директорий?", default=False)
    wordlist = Prompt.ask("Путь к файлу словаря") if use_custom else None
    concurrency = IntPrompt.ask("Количество одновременных запросов (concurrency)", default=30)
    async with StructureScanner(url, concurrency=concurrency) as scanner:
        report = await scanner.run(wordlist_path=wordlist)
    print_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


async def run_response():
    console.print("\n[cyan]URL цели[/] (например, http://ctf.example.com/login):")
    url = Prompt.ask(">>>")
    flag_prefix = Prompt.ask("[cyan]Префикс флага[/] (например, grodno, HTB; Enter — не искать)", default="")
    if not flag_prefix:
        console.print("[yellow]⚠ Префикс не указан — поиск флагов отключён[/]")
    analyzer = ResponseAnalyzer(url, flag_prefix=flag_prefix)
    reports = await analyzer.analyze()
    for r in reports:
        print_response_report(r)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


def run_cookie():
    console.print("\n[cyan]Префикс флага[/] (например, grodno, ctf, HTB; Enter — не искать):")
    flag_prefix = Prompt.ask(">>>", default="")
    if not flag_prefix:
        console.print("[yellow]⚠ Префикс не указан — поиск флагов отключён[/]")
    console.print("\n[cyan]Введите куки[/] в формате name=value (по одной на строку, пустая строка — конец ввода):")
    cookies = []
    while True:
        line = Prompt.ask(">>>").strip()
        if not line:
            break
        if "=" in line:
            name, value = line.split("=", 1)
            cookies.append({"name": name.strip(), "value": value.strip()})
    if cookies:
        analyzer = CookieAnalyzer(flag_prefix=flag_prefix)
        for analysis in analyzer.analyze_batch(cookies):
            print_cookie_analysis(analysis)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


def run_jwt():
    console.print("\n[bold cyan]═══ JWT-ИНСТРУМЕНТ ═══[/]")
    console.print("[green]1[/] Декодировать токен")
    console.print("[green]2[/] Создать токен с алгоритмом 'none'")
    console.print("[green]3[/] Подобрать секретный ключ (брутфорс)")
    console.print("[green]4[/] Изменить payload")
    console.print("[yellow]0[/] Назад")
    choice = IntPrompt.ask(">>>", choices=["0", "1", "2", "3", "4"])
    if choice == 0:
        return
    if choice == 1:
        token = Prompt.ask("[cyan]Введите JWT-токен[/]")
        tool = JWTTool()
        print_jwt_analysis(tool.decode_token(token))
    elif choice == 2:
        console.print("[dim]Пример: {\"user\": \"admin\", \"is_admin\": true}[/]")
        payload_str = Prompt.ask("[cyan]Payload (JSON)[/]")
        try:
            payload = json.loads(payload_str)
            tool = JWTTool()
            console.print(f"\n[bold green]Новый токен (alg:none):[/]\n{tool.create_none_token(payload)}")
        except json.JSONDecodeError as e:
            console.print(f"[red]Некорректный JSON: {e}[/]")
    elif choice == 3:
        token = Prompt.ask("[cyan]Введите JWT-токен[/]")
        use_custom = Confirm.ask("Использовать свой словарь?", default=False)
        wordlist = Prompt.ask("Путь к файлу словаря") if use_custom else None
        tool = JWTTool(wordlist_path=wordlist)
        console.print("[dim]Выполняется подбор...[/]")
        secret = tool.brute_force_secret(token)
        if secret:
            console.print(f"[bold red]🔑 СЕКРЕТНЫЙ КЛЮЧ НАЙДЕН: {secret}[/]")
        else:
            console.print("[yellow]Секретный ключ в словаре не найден[/]")
    elif choice == 4:
        token = Prompt.ask("[cyan]Введите исходный JWT-токен[/]")
        console.print("[dim]Пример: {\"is_admin\": true}[/]")
        mod_str = Prompt.ask("[cyan]Изменения (JSON)[/]")
        try:
            modifications = json.loads(mod_str)
            tool = JWTTool()
            analysis = tool.modify_payload(token, modifications)
            console.print(f"\n[bold yellow]Изменённый payload:[/]\n{json.dumps(analysis.payload, indent=2)}")
        except json.JSONDecodeError as e:
            console.print(f"[red]Некорректный JSON: {e}[/]")
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


async def run_cors():
    console.print("\n[bold cyan]═══ CORS-СКАНЕР ═══[/]")
    console.print("[dim]Проверяет 8 векторов: null origin, отражение, wildcard, поддомены, regex, HTTP-downgrade, preflight.[/]")
    url = Prompt.ask("\n[cyan]URL цели[/]")
    console.print("[cyan]Дополнительные заголовки[/] (формат: 'Key: Value', по одному на строку; Enter — пропустить):")
    headers_raw = Prompt.ask(">>>", default="")
    cookies = Prompt.ask("[cyan]Cookie[/] (например, session=abc123; Enter — пропустить)", default="")
    custom_headers = {}
    if headers_raw:
        for line in headers_raw.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                custom_headers[k.strip()] = v.strip()
    scanner = CORSScanner(url, custom_headers=custom_headers or None, cookies=cookies or None)
    report = await scanner.scan()
    print_cors_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


async def run_username_recon():
    console.print("\n[bold cyan]═══ ПРОВЕРКА ИДЕНТИФИКАТОРОВ ═══[/]")
    console.print("[dim]Проверяет никнейм на 10 платформах:[/]")
    console.print("[dim]GitHub, GitLab, Docker Hub, Kaggle, HackTheBox, TryHackMe,[/]")
    console.print("[dim]Reddit, Twitter/X, Telegram, Steam.[/]")
    console.print("\n[cyan]Никнейм для проверки[/] (например, torvalds):")
    username = Prompt.ask(">>>").strip().lstrip("@")
    if not username:
        console.print("[red]Никнейм не указан[/]")
        return
    console.print(f"\n[dim]Проверяю {username} на всех платформах...[/]")
    recon = UsernameRecon()
    report = await recon.scan(username)
    print_username_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


async def run_repo_search():
    console.print("\n[bold cyan]═══ ПОИСК РЕПОЗИТОРИЕВ (GitHub) ═══[/]")
    console.print("[dim]Анализирует публичные репозитории:[/]")
    console.print("[dim]• Список всех репозиториев[/]")
    console.print("[dim]• Поиск .env, id_rsa, конфигов[/]")
    console.print("[dim]• Поиск API-ключей, паролей, JWT, флагов[/]")
    username = Prompt.ask("\n[cyan]Никнейм на GitHub[/]").strip().lstrip("@")
    if not username:
        console.print("[red]Никнейм не указан[/]")
        return
    flag_prefix = Prompt.ask("[cyan]Префикс флага[/] (Enter — не искать)", default="")
    github_token = Prompt.ask("[cyan]GitHub token[/] [dim](Enter — без, 60 req/h; с токеном 5000 req/h)[/]", default="")
    if not flag_prefix:
        console.print("[yellow]⚠ Префикс не указан — поиск флагов отключён[/]")
    console.print(f"\n[dim]Сканирую репозитории {username}...[/]")
    searcher = RepoSearch(github_token=github_token or None, flag_prefix=flag_prefix)
    report = await searcher.scan_github(username)
    print_repo_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


async def run_whois_geoip():
    console.print("\n[bold cyan]═══ WHOIS & GEOIP ═══[/]")
    console.print("[dim]Получает регистрационные данные домена:[/]")
    console.print("[dim]• Регистратор, даты создания/истечения[/]")
    console.print("[dim]• Владелец, организация, email-адреса[/]")
    console.print("[dim]• NS-серверы и статусы[/]")
    console.print("[dim]Определяет геолокацию IP-адреса:[/]")
    console.print("[dim]• Страна, регион, город, провайдер[/]")
    console.print("[dim]• Координаты + ссылка на Google Maps[/]")
    console.print("\n[cyan]Домен или IP[/] (например, example.com, 8.8.8.8, https://ctf.site.com):")
    target = Prompt.ask(">>>").strip()
    if not target:
        console.print("[red]Цель не указана[/]")
        return
    console.print(f"\n[dim]Запрашиваю WHOIS и GeoIP для {target}...[/]")
    checker = WhoisGeoIPChecker()
    report = await checker.check(target)
    print_whois_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
    

async def run_subdomain_enum():
    console.print("\n[bold cyan]═══ SUBDOMAIN ENUMERATOR ═══[/]")
    console.print("[dim]Ищет поддомены через 3 публичных источника:[/]")
    console.print("[dim]• crt.sh — SSL-сертификаты (самый мощный)[/]")
    console.print("[dim]• HackerTarget — пассивный DNS[/]")
    console.print("[dim]• AlienVault OTX — открытые угрозы[/]")
    console.print("[dim]Затем проверяет каждый поддомен (DNS + HTTP).[/]")

    target = Prompt.ask("\n[cyan]Домен[/] (например, example.com)").strip()
    if not target:
        console.print("[red]Домен не указан[/]")
        return
    check_http = Confirm.ask("[cyan]Проверять HTTP-доступность?[/] [dim](медленнее, но информативнее)[/]", default=True)
    concurrency = IntPrompt.ask("[cyan]Concurrent запросов[/]", default=25)

    console.print(f"\n[dim]Собираю поддомены для {target}...[/]")
    enum = SubdomainEnumerator(concurrency=concurrency, check_http=check_http)
    report = await enum.scan(target)
    print_subdomain_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


async def run_dns_recon():
    console.print("\n[bold cyan]═══ DNS RECONNAISSANCE ═══[/]")
    console.print("[dim]Запрашивает все типы DNS-записей:[/]")
    console.print("[dim]• A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV[/]")
    console.print("[dim]• DMARC (_dmarc.domain)[/]")
    console.print("[dim]• DKIM (default._domainkey.domain)[/]")
    console.print("[dim]Ищет флаги в TXT-записях и subdomain takeover в CNAME.[/]")

    target = Prompt.ask("\n[cyan]Домен[/] (например, example.com)").strip()
    if not target:
        console.print("[red]Домен не указан[/]")
        return
    flag_prefix = Prompt.ask("[cyan]Префикс флага[/] (Enter — не искать)", default="")
    if not flag_prefix:
        console.print("[yellow]⚠ Префикс не указан — поиск флагов в TXT отключён[/]")

    console.print(f"\n[dim]Запрашиваю DNS-записи для {target}...[/]")
    recon = DNSRecon(flag_prefix=flag_prefix)
    report = await recon.scan(target)
    print_dns_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


async def run_wayback():
    console.print("\n[bold cyan]═══ WAYBACK MACHINE ANALYZER ═══[/]")
    console.print("[dim]Получает всю историю сайта через archive.org:[/]")
    console.print("[dim]• До 5000 уникальных URL за один запрос[/]")
    console.print("[dim]• Фильтрует подозрительные:[/]")
    console.print("[dim]  .git, .env, backup, flag, admin, .sql, password, api/, dev/[/]")
    console.print("[dim]• Показывает прямые ссылки на архивные снапшоты[/]")

    target = Prompt.ask("\n[cyan]Домен[/] (например, example.com)").strip()
    if not target:
        console.print("[red]Домен не указан[/]")
        return
    flag_prefix = Prompt.ask("[cyan]Префикс флага[/] (Enter — не искать)", default="")
    if not flag_prefix:
        console.print("[yellow]⚠ Префикс не указан — поиск флагов в URL отключён[/]")

    console.print(f"\n[dim]Запрашиваю историю {target} (это может занять 10-30 сек)...[/]")
    analyzer = WaybackAnalyzer(flag_prefix=flag_prefix)
    report = await analyzer.scan(target)
    print_wayback_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
    

# ═══════════════ Обработчики меню ═══════════════

def handle_web():
    while True:
        choice = web_menu()
        if choice == 0:
            return
        if choice == 1:
            asyncio.run(run_structure())
        elif choice == 2:
            asyncio.run(run_response())
        elif choice == 3:
            run_cookie()
        elif choice == 4:
            run_jwt()
        elif choice == 5:
            asyncio.run(run_cors())
        elif choice == 6:
            asyncio.run(run_subdomain_enum())
        elif choice == 7:
            asyncio.run(run_dns_recon())
        elif choice == 8:
            asyncio.run(run_wayback())


def handle_osint():
    while True:
        choice = osint_menu()
        if choice == 0:
            return
        if choice == 1:
            asyncio.run(run_username_recon())
        elif choice == 2:
            asyncio.run(run_repo_search())
        elif choice == 3:
            asyncio.run(run_whois_geoip())
        else:
            console.print("[yellow]Этот модуль ещё не реализован[/]")
            Prompt.ask("[dim]Enter, чтобы продолжить[/]")


def main():
    try:
        while True:
            choice = main_menu()
            if choice == 0:
                console.print("[magenta]До встречи![/]")
                sys.exit(0)
            if choice == 1:
                handle_web()
            elif choice == 2:
                handle_osint()
    except KeyboardInterrupt:
        console.print("\n[magenta]Прервано[/]")
        sys.exit(0)


if __name__ == "__main__":
    main()