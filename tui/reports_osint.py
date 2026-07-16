"""
Вывод отчётов модуля OSINT.
Перенесено из main_osint_web.py без изменения логики.
"""
from . import console


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
