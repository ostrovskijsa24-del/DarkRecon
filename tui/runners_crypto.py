"""
Запуск модуля Crypto.

Обёртка над modules.crypto.analyzer.analyze_crypto и
modules.crypto.output.print_probable_flags. Автоматически
перебирает Base64/Hex/Цезарь/ROT/Affine/XOR и рекурсивно
раскручивает цепочки декодирования.
"""
from __future__ import annotations

from rich.prompt import Prompt, IntPrompt, Confirm

from . import console

from modules.crypto.analyzer import analyze_crypto
from modules.crypto.output import print_probable_flags


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
        # Модуль crypto выводит через plain print — оставляем как есть.
        print_probable_flags(results, limit=limit)
    except Exception as error:
        console.print(f"[red]Ошибка анализа:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
