"""
Запуск модулей OSINT.
Перенесено из main_osint_web.py без изменения логики.
"""
from rich.prompt import Prompt

from . import console
from .reports_osint import print_username_report, print_repo_report, print_whois_report
from modules.osint.username_recon import UsernameRecon
from modules.osint.repo_search import RepoSearch
from modules.osint.whois_geoip import WhoisGeoIPChecker


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
