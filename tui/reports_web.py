"""
Вывод отчётов модуля Web-безопасности.
Перенесено из main_osint_web.py без изменения логики.
"""
import json

from rich.prompt import Confirm

from . import console


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
