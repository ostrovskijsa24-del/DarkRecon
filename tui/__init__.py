"""
tui — консольный интерфейс DarkRecon.

Пакет разбит по ответственности:
- menus        — отрисовка меню
- reports_*    — форматированный вывод отчётов (web / osint)
- runners_*    — запуск отдельных модулей (web / osint / stego / crypto / forensics)
- handlers     — циклы обработки подменю
"""
from rich.console import Console

# Единая консоль для всего интерфейса.
console = Console()

__all__ = ["console"]
