"""
Запуск модуля Crypto.
"""
from __future__ import annotations

from pathlib import Path
from rich.prompt import Prompt

from . import console
from .reports_crypto import print_and_save_report

from modules.crypto.analyzer import analyze_crypto


def _ask_output_dir() -> Path:
    """
    Строго запрашивает папку для сохранения отчета (как в Stego).
    Пустой ввод не принимается.
    """
    while True:
        user_input = Prompt.ask("[cyan]Укажите папку для сохранения отчета (например, . или /tmp)[/]").strip()
        if user_input:
            return Path(user_input)
        console.print("[yellow]Путь не может быть пустым.[/]")


def run_crypto():
    console.print("\n[bold cyan]═══ АНАЛИЗ СТРОКИ (CRYPTO) ═══[/]")
    console.print("[dim]Авто-декодер: Base64/Hex/Цезарь/ROT/Affine/XOR.[/]")

    data = Prompt.ask("\n[cyan]Введите строку или данные для анализа[/]")
    if not data.strip():
        console.print("[red]Пустой ввод[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    # Запрашиваем префикс флага (как в Web)
    flag_prefix = Prompt.ask("[cyan]Префикс флага[/] [dim](например, grodno, ctf; Enter — стандартные)[/]", default="")
    
    # Запрашиваем путь сохранения (как в Stego)
    output_dir = _ask_output_dir()
    output_file = output_dir / "crypto_report.txt"

    console.print("\n[dim]Анализирую (рекурсивно, глубина = 2)...[/]")
    try:
        # Бизнес-логика анализа
        results = analyze_crypto(data, recursive=True, max_depth=2)
        
        # Передаем всё в модуль отрисовки и сохранения
        print_and_save_report(results, output_file, flag_prefix=flag_prefix, limit=7)
    except Exception as error:
        from rich.markup import escape
        console.print(f"[red]Ошибка анализа:[/] {escape(str(error))}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")