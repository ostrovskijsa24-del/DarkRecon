"""
Запуск модулей Web-безопасности.
Перенесено из main_osint_web.py без изменения логики.
"""
import json

from rich.prompt import Prompt, IntPrompt, Confirm

from . import console
from .reports_web import (
    print_report, print_response_report, print_cookie_analysis,
    print_jwt_analysis, print_cors_report,
)
from modules.web.structure_scanner import StructureScanner
from modules.web.response_analyzer import ResponseAnalyzer
from modules.web.cookie_analyzer import CookieAnalyzer
from modules.web.jwt_tool import JWTTool
from modules.web.cors_scanner import CORSScanner
from modules.web.subdomain_enum import SubdomainEnumerator
from modules.web.dns_recon import DNSRecon
from modules.web.wayback_analyzer import WaybackAnalyzer


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
    from .reports_osint import print_subdomain_report
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
    from .reports_osint import print_dns_report
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
    from .reports_osint import print_wayback_report
    print_wayback_report(report)
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
