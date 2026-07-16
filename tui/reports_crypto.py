"""
Вывод отчётов модуля Crypto.
"""
from __future__ import annotations

from rich.markup import escape

from . import console
from modules.crypto.flags import extract_flag_candidate, select_probable_flags


def print_probable_flags(results: list[dict], limit: int = 7) -> None:
    """
    Показывает наиболее вероятные кандидаты-флаги.
    """
    selected = select_probable_flags(results, limit)
    if not selected:
        console.print("[yellow]Подходящих кандидатов не найдено.[/]")
        return

    console.print("\n[bold cyan]═══ TOP PROBABLE FLAGS ═══[/]")
    for number, result in enumerate(selected, start=1):
        _print_compact_result(result, number)


def _print_compact_result(result: dict, number: int) -> None:
    score = float(result.get("score", 0.0))
    chain = " -> ".join(result.get("chain", [])) or result.get("method", "unknown")
    candidate = extract_flag_candidate(str(result.get("result", "")))
    
    # Экранируем строки, так как в расшифрованном тексте или цепочке могут быть скобки [ ]
    safe_chain = escape(chain)
    safe_candidate = escape(candidate)

    error = result.get("error")
    if error:
        safe_error = escape(str(error))
        console.print(f"  [red]{number}. \\[[ERROR]\\][/red] [cyan]{safe_chain}[/cyan]: {safe_error}")
        return
        
    # Двойные слеши \\[ экранируют квадратные скобки, чтобы они вывелись как обычные символы
    console.print(f"  [green]{number}.[/] \\[[bold]{score:.4f}[/bold]\\] [cyan]{safe_chain}[/cyan]: {safe_candidate}")