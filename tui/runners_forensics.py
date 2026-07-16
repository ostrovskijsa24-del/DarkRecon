"""
Запуск модуля Forensics.

Спрашивает у пользователя входной файл и папку для сохранения.
Параметры анализа (размер чанка и лимит вывода) зафиксированы по умолчанию.
"""
from __future__ import annotations

import sys
from pathlib import Path

from rich.prompt import Prompt

from . import console
from .reports_forensics import print_and_save_forensics_report

from modules.forensics.analyzer import analyze_forensics

PROJECT_ROOT = Path(__file__).resolve().parents[1]


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


def _ask_output_dir() -> Path:
    """
    Строго запрашивает папку для сохранения отчета (как в Stego и Crypto).
    Пустой ввод не принимается.
    """
    while True:
        user_input = Prompt.ask("[cyan]Укажите папку для сохранения отчета (например, . или /tmp)[/]").strip()
        if user_input:
            return Path(user_input)
        console.print("[yellow]Путь не может быть пустым.[/]")


def run_forensics():
    console.print("\n[bold cyan]═══ АНАЛИЗ ФАЙЛА (FORENSICS) ═══[/]")
    console.print("[dim]Определяет тип файла по сигнатуре, считает энтропию,[/]")
    console.print("[dim]извлекает строки, считает хеши и ищет вложенные файлы (карвинг).[/]")

    user_path = Prompt.ask("\n[cyan]Путь к файлу[/] (относительно проекта или абсолютный)")
    if not user_path.strip():
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    output_dir = _ask_output_dir()
    output_file = output_dir / "forensics_report.txt"

    try:
        resolved_path = resolve_input_path(user_path.strip())
    except FileNotFoundError as error:
        console.print(f"[red]Ошибка:[/] {error}")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    console.print(f"\n[dim]Анализирую {resolved_path} (чанк=1024)...[/]")
    try:
        chunk_size = 1024
        limit = 10

        result = analyze_forensics(resolved_path, chunk_size=chunk_size)
        
        print_and_save_forensics_report(result, output_file, limit=limit)
    except Exception as error:
        console.print(f"[red]Ошибка анализа:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")