"""
Вывод отчётов модуля Forensics.

Чистая презентация: рисует результат анализа файла через rich.
Данные формирует бизнес-логика modules.forensics.analyzer.analyze_forensics.
"""
from __future__ import annotations

from . import console


def print_feed(result: dict, limit: int = 10) -> None:
    """
    Краткий отчёт по результатам forensics-анализа: метаданные, проверки,
    вложенные сигнатуры и интересные строки.
    """
    metadata = result.get("metadata", {})
    signature = result.get("signature", {})
    entropy = result.get("entropy", {})
    hashes = result.get("hashes", {})
    extension_check = result.get("extension_check", {})
    embedded_files = result.get("embedded_files", [])
    interesting = result.get("strings", {}).get("interesting", [])

    console.print("\n[bold cyan]═══ Анализ файла ═══[/]")
    console.print(f"[bold]Файл:[/] {metadata.get('name', result.get('source'))}")
    console.print(f"[bold]Размер:[/] {_format_size(metadata.get('size', 0))}")
    console.print(f"[bold]Тип:[/] [yellow]{signature.get('type', 'unknown')}[/]")
    console.print(f"[bold]SHA256:[/] [dim]{hashes.get('sha256')}[/]")

    console.print("\n[bold]═══ Проверки ═══[/]")
    console.print(
        f"[bold]Энтропия:[/] {entropy.get('value')} — {entropy.get('assessment')}"
    )
    if extension_check.get("checked"):
        status = (
            "[red]не совпадает[/]" if extension_check.get("mismatch")
            else "[green]совпадает[/]"
        )
        console.print(f"[bold]Расширение и сигнатура:[/] {status}")
    else:
        console.print("[bold]Расширение и сигнатура:[/] [dim]не проверялось[/]")

    console.print("\n[bold]═══ Находки ═══[/]")
    if embedded_files:
        console.print(f"[bold]Вложенные сигнатуры:[/] {len(embedded_files)}")
        for item in embedded_files[:limit]:
            console.print(f"  • [yellow]{item['type']}[/] на смещении {item['offset_hex']}")
        if len(embedded_files) > limit:
            console.print(f"  [dim]… ещё {len(embedded_files) - limit} скрыто в кратком выводе[/]")
    else:
        console.print("[dim]Вложенные сигнатуры не найдены[/]")

    if interesting:
        console.print("\n[bold]═══ Интересные строки ═══[/]")
        for item in interesting[:limit]:
            console.print(
                f"  • [[yellow]{item['kind']}[/]] {item['offset_hex']}: "
                f"{_trim(item['value'])}"
            )
        if len(interesting) > limit:
            console.print(f"  [dim]… ещё {len(interesting) - limit} скрыто в кратком выводе[/]")
    else:
        console.print("[dim]Интересные строки не найдены[/]")


def _format_size(size: int | None) -> str:
    if not size:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def _trim(text: str, limit: int = 120) -> str:
    clean = text.replace("\n", "\\n").replace("\r", "\\r")
    return clean if len(clean) <= limit else clean[: limit - 3] + "..."
