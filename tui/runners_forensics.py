"""
Запуск модуля Forensics.

Обёртка над бизнес-логикой modules.forensics.analyzer.analyze_forensics.
Вывод — в tui/reports_forensics.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

from rich.prompt import Prompt, IntPrompt

from . import console
from .reports_forensics import print_feed

# Точка входа в проект нужна для resolve_input_path (поиск по PROJECT_ROOT).
PROJECT_ROOT = Path(__file__).resolve().parents[1]

from modules.forensics.analyzer import analyze_forensics


def _unique_paths(paths: list[Path]) -> list[Path]:
    unique = []
    seen = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path.absolute())
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def resolve_input_path(user_input: str) -> Path:
    """Ищет файл в нескольких стандартных местах; подсказывает при неоднозначности."""
    raw_path = Path(user_input).expanduser()
    search_places = _unique_paths([
        raw_path,
        Path.cwd() / raw_path,
        Path(__file__).resolve().parent / raw_path,
        PROJECT_ROOT / raw_path,
    ])

    for path in search_places:
        if path.is_file():
            return path.resolve()

    if len(raw_path.parts) == 1:
        matches = [path for path in PROJECT_ROOT.rglob(raw_path.name) if path.is_file()]
        if len(matches) == 1:
            return matches[0].resolve()
        if len(matches) > 1:
            console.print("[yellow]Найдено несколько файлов с таким именем:[/]")
            for number, path in enumerate(matches, start=1):
                console.print(f"  {number}. {path}")
            raise FileNotFoundError("укажите более точный путь к файлу")

    checked = "\n".join(f"- {path}" for path in search_places)
    raise FileNotFoundError(f"файл не найден. Проверенные места:\n{checked}")


def run_forensics():
    console.print("\n[bold cyan]═══ АНАЛИЗ ФАЙЛА (FORENSICS) ═══[/]")
    console.print("[dim]Определяет тип файла по сигнатуре, считает энтропию,[/]")
    console.print("[dim]извлекает строки, считает хеши и ищет вложенные файлы (карвинг).[/]")

    user_path = Prompt.ask("\n[cyan]Путь к файлу[/] (относительно проекта или абсолютный)")
    if not user_path.strip():
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    chunk_size = IntPrompt.ask("[cyan]Размер чанка для энтропии[/]", default=1024)
    limit = IntPrompt.ask("[cyan]Сколько находок выводить[/]", default=10)

    try:
        resolved_path = resolve_input_path(user_path.strip())
    except FileNotFoundError as error:
        console.print(f"[red]Ошибка:[/] {error}")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    console.print(f"\n[dim]Анализирую {resolved_path}...[/]")
    try:
        result = analyze_forensics(resolved_path, chunk_size=chunk_size)
        print_feed(result, limit=limit)
    except Exception as error:
        console.print(f"[red]Ошибка анализа:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
