"""
DarkRecon — точка входа.

Главное меню и диспетчер подменю. Вся логика UI вынесена в пакет `tui/`:
- tui/menus        — отрисовка меню
- tui/reports_*    — вывод отчётов
- tui/runners_*    — запуск модулей (web / osint / stego / crypto / forensics)
- tui/handlers     — циклы подменю
"""
import sys

from rich.console import Console

from tui.menus import main_menu
from tui.handlers import (
    handle_web, handle_osint, handle_stego, handle_crypto, handle_forensics,
)

console = Console()

_DISPATCH = {
    1: handle_web,
    2: handle_osint,
    3: handle_stego,
    4: handle_crypto,
    5: handle_forensics,
}


def main():
    try:
        while True:
            choice = main_menu()
            if choice == 0:
                console.print("[magenta]До встречи![/]")
                sys.exit(0)
            _DISPATCH[choice]()
    except KeyboardInterrupt:
        console.print("\n[magenta]Прервано[/]")
        sys.exit(0)


if __name__ == "__main__":
    main()
