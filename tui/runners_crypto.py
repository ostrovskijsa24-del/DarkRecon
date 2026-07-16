"""
Запуск модуля Crypto.

Обёртка над бизнес-логикой modules.crypto.analyzer.analyze_crypto.
Автоматически перебирает Base64/Hex/Цезарь/ROT/Affine/XOR и рекурсивно
раскручивает цепочки декодирования. Вывод — в tui/reports_crypto.py.
"""
from __future__ import annotations

from rich.prompt import Prompt, IntPrompt, Confirm

from . import console
from .reports_crypto import print_probable_flags

from modules.crypto.analyzer import analyze_crypto


def run_crypto():
    console.print("\n[bold cyan]═══ АНАЛИЗ СТРОКИ (CRYPTO) ═══[/]")
    console.print("[dim]Авто-декодер: Base64/Base32/Hex/URL, Цезарь, ROT13/47, Atbash,[/]")
    console.print("[dim]Affine, single-byte XOR, repeating-key XOR.[/]")
    console.print("[dim]Рекурсивно раскручивает цепочки и ранжирует результаты по «читаемости».[/]")

    data = Prompt.ask("\n[cyan]Введите строку или данные для анализа[/]")
    if not data.strip():
        console.print("[red]Пустой ввод[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    recursive = Confirm.ask("[cyan]Рекурсивный декод?[/]", default=True)
    max_depth = IntPrompt.ask("[cyan]Максимальная глубина[/]", default=2)
    limit = IntPrompt.ask("[cyan]Сколько лучших кандидатов показать[/]", default=7)

    console.print("\n[dim]Анализирую...[/]")
    try:
        results = analyze_crypto(data, recursive=recursive, max_depth=max_depth)
        print_probable_flags(results, limit=limit)
    except Exception as error:
        from rich.markup import escape
        safe_error = escape(str(error))
        console.print(f"[red]Ошибка анализа:[/] {safe_error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
