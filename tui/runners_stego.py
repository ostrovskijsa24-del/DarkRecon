"""
Запуск модулей Stego.

Каждый раннер запрашивает путь к файлу (ручной ввод или системный диалог),
создаёт соответствующий класс-анализатор из modules.stego и вызывает
его точки входа (analyze / save). Вся интерактивность — здесь.

Результаты анализа рисуются через tui/reports_stego.py.
"""
from __future__ import annotations

from pathlib import Path

from rich.prompt import Prompt, Confirm, IntPrompt
from rich.console import Console

from . import console
from .reports_stego import (
    print_statistics, print_palette, print_png_structure,
    print_audio_info, print_saved_files,
)

from modules.stego.bitplanes import BitPlaneAnalyzer
from modules.stego.combine_planes import PlaneCombiner
from modules.stego.xor_planes import XorPlaneAnalyzer
from modules.stego.statistics import StatisticsAnalyzer
from modules.stego.palette import PaletteAnalyzer
from modules.stego.png_structure import PNGStructureAnalyzer
from modules.stego.audio import AudioAnalyzer
from modules.stego.file_dialog import FileDialog

# Корневая директория проекта (для resolve_input_path).
PROJECT_ROOT = Path(__file__).resolve().parents[1]


# ─── Утилиты ввода ──────────────────────────────────────────────────

def _ask_path(kind: str = "файл") -> str | None:
    """
    Запрос пути к файлу: ручной ввод через rich или системный диалог.
    Возвращает путь или None, если пользователь отменил ввод.
    """
    use_dialog = Confirm.ask(
        f"[cyan]Выбрать {kind} в диалоге?[/] [dim](иначе — ввести путь вручную)[/]",
        default=False,
    )
    if use_dialog:
        try:
            path = FileDialog.select_file()
        except Exception as error:
            console.print(f"[yellow]Не удалось открыть диалог ({error}); введите путь вручную.[/]")
            path = ""
        if path:
            return path
        console.print("[yellow]Файл не выбран — введите путь вручную.[/]")
    path = Prompt.ask(f"[cyan]Путь к {kind}[/]").strip()
    return path or None


def _ask_output_dir(default_suffix: str) -> Path:
    """Дефолт — папка 'stego_output' в том месте, откуда запущен скрипт."""
    default_path = str(Path.cwd() / "stego_output" / default_suffix)
    
    user_input = Prompt.ask(
        f"[cyan]Куда сохранить результаты?[/] [dim](Enter — {default_path})[/]",
        default=default_path,
    ).strip()
    return Path(user_input)


# ═════════════ Bitplanes ═════════════

def run_bitplanes():
    console.print("\n[bold cyan]═══ БИТОВЫЕ ПЛОСКОСТИ ═══[/]")
    console.print("[dim]Извлекает битовые плоскости каждого канала изображения[/]")
    console.print("[dim](полезно для визуального поиска LSB-стеганографии).[/]")

    path = _ask_path("изображению")
    if not path:
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    try:
        analyzer = BitPlaneAnalyzer(path)
        report = analyzer.analyze()

        console.print(f"\n[dim]Анализ: {report['image']}, "
                      f"{len(report['channels'])} каналов по 8 плоскостей.[/]")

        if Confirm.ask("[cyan]Сохранить плоскости?[/]", default=True):
            output_dir = _ask_output_dir(f"bitplanes/{analyzer.image_name}")
            paths = analyzer.save(output_dir)
            print_saved_files(paths, "Плоскости")
    except Exception as error:
        console.print(f"[red]Ошибка:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


# ═════════════ Combine planes ═════════════

def _combine_submenu() -> tuple[int, int] | None:
    """
    Подменю выбора режима генерации комбинаций.
    Возвращает (min_bits, max_bits) или None при отмене.
    """
    console.print("\n[yellow]Выберите режим генерации:[/]")
    console.print("[green]1[/] Комбинации по 2 бита")
    console.print("[green]2[/] Комбинации по 3 бита")
    console.print("[green]3[/] Комбинации по 4 бита")
    console.print("[green]4[/] Все комбинации (2-8)")
    console.print("[green]5[/] Свой диапазон")
    console.print("[yellow]0[/] Назад")

    choice = IntPrompt.ask(">>>", choices=["0", "1", "2", "3", "4", "5"])
    if choice == 0:
        return None
    if choice == 1:
        return (2, 2)
    if choice == 2:
        return (3, 3)
    if choice == 3:
        return (4, 4)
    if choice == 4:
        return (2, 8)
    # choice == 5 — свой диапазон
    try:
        minimum = IntPrompt.ask("[cyan]Минимум бит[/]")
        maximum = IntPrompt.ask("[cyan]Максимум бит[/]")
        return (minimum, maximum)
    except Exception:
        console.print("[red]Ошибка ввода.[/]")
        return None


def run_combine():
    console.print("\n[bold cyan]═══ ОБЪЕДИНЕНИЕ ПЛОСКОСТЕЙ ═══[/]")
    console.print("[dim]Собирает изображение из выбранных битовых плоскостей[/]")
    console.print("[dim](например, младшие биты — потенциально скрытое сообщение).[/]")

    path = _ask_path("изображению")
    if not path:
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    try:
        combiner = PlaneCombiner(path)
        channel_names = combiner.CHANNEL_NAMES[:len(combiner.channels)]

        while True:
            console.print("\n[yellow]1[/] Создать все комбинации")
            console.print("[yellow]2[/] Создать выбранную комбинацию")
            console.print("[yellow]0[/] Назад")
            choice = IntPrompt.ask(">>>", choices=["0", "1", "2"])
            if choice == 0:
                break

            output_dir = _ask_output_dir(f"combine/{combiner.image_name}")

            if choice == 1:
                bits_range = _combine_submenu()
                if bits_range is None:
                    continue
                console.print("[dim]Генерирую комбинации…[/]")
                paths = combiner.combine_all(output_dir, *bits_range)
                print_saved_files(paths, "Комбинации")

            elif choice == 2:
                console.print("\n[yellow]Каналы:[/]")
                for idx, name in enumerate(channel_names):
                    console.print(f"  [green]{idx + 1}.[/] {name}")

                try:
                    channel = IntPrompt.ask("[cyan]Номер канала[/]") - 1
                    bits_str = Prompt.ask(
                        "[cyan]Номера битов через пробел[/]",
                        default="0 1",
                    )
                    bits = [int(b) for b in bits_str.split()]
                except ValueError:
                    console.print("[red]Ошибка ввода.[/]")
                    continue

                console.print("[dim]Объединяю…[/]")
                paths = combiner.combine_selected(channel, bits, output_dir)
                print_saved_files(paths, "Комбинация")
    except Exception as error:
        console.print(f"[red]Ошибка:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


# ═════════════ XOR planes ═════════════

def run_xor():
    console.print("\n[bold cyan]═══ XOR ПЛОСКОСТЕЙ ═══[/]")
    console.print("[dim]XOR-анализ битовых плоскостей для выявления скрытых данных.[/]")

    path = _ask_path("изображению")
    if not path:
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    try:
        analyzer = XorPlaneAnalyzer(path)
        report = analyzer.analyze()

        console.print(
            f"\n[dim]XOR-пар: {report['count']} для {report['image']}.[/]"
        )

        if Confirm.ask("[cyan]Сохранить XOR-изображения?[/]", default=True):
            output_dir = _ask_output_dir(f"xor/{analyzer.image_name}")
            paths = analyzer.save(output_dir)
            print_saved_files(paths, "XOR-изображения")
    except Exception as error:
        console.print(f"[red]Ошибка:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


# ═════════════ Statistics ═════════════

def run_statistics():
    console.print("\n[bold cyan]═══ СТАТИСТИКА ИЗОБРАЖЕНИЯ ═══[/]")
    console.print("[dim]Гистограммы и статистика распределения пикселей[/]")
    console.print("[dim](аномалии могут указывать на встроенные данные).[/]")

    path = _ask_path("изображению")
    if not path:
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    try:
        analyzer = StatisticsAnalyzer(path)
        report = analyzer.analyze()
        print_statistics(report)
    except Exception as error:
        console.print(f"[red]Ошибка:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


# ═════════════ Palette ═════════════

def run_palette():
    console.print("\n[bold cyan]═══ АНАЛИЗ ПАЛИТРЫ ═══[/]")
    console.print("[dim]Анализ палитры PNG (скрытые/неиспользуемые цвета, аномалии).[/]")

    path = _ask_path("PNG")
    if not path:
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    try:
        analyzer = PaletteAnalyzer(path)
        report = analyzer.analyze()
        print_palette(report)

        if report["has_palette"]:
            if Confirm.ask("[cyan]Сохранить изображение палитры?[/]", default=False):
                output_dir = _ask_output_dir("palette")
                saved = analyzer.save(output_dir)
                console.print(f"[green][+] Палитра сохранена:[/] {saved}")
    except Exception as error:
        console.print(f"[red]Ошибка:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


# ═════════════ PNG structure ═════════════

def run_png_structure():
    console.print("\n[bold cyan]═══ СТРУКТУРА PNG ═══[/]")
    console.print("[dim]Разбор чанков PNG, поиск скрытых данных после IEND[/]")
    console.print("[dim]или в нестандартных/повторных чанках.[/]")

    path = _ask_path("PNG")
    if not path:
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    try:
        analyzer = PNGStructureAnalyzer(path)
        report = analyzer.analyze()
        print_png_structure(report)
    except Exception as error:
        console.print(f"[red]Ошибка:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


# ═════════════ Audio ═════════════

def run_audio():
    console.print("\n[bold cyan]═══ АНАЛИЗ АУДИО (WAV) ═══[/]")
    console.print("[dim]LSB в сэмплах, метаданные и спектрограмма аудиофайла.[/]")

    path = _ask_path("WAV")
    if not path:
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return

    try:
        analyzer = AudioAnalyzer(path)

        while True:
            console.print("\n[yellow]1[/] Информация о WAV")
            console.print("[yellow]2[/] Извлечь LSB поток")
            console.print("[yellow]0[/] Назад")
            choice = IntPrompt.ask(">>>", choices=["0", "1", "2"])
            if choice == 0:
                break

            if choice == 1:
                print_audio_info(analyzer.info())

            elif choice == 2:
                if Confirm.ask("[cyan]Сохранить LSB-поток?[/]", default=True):
                    output_dir = _ask_output_dir(f"audio/{analyzer.image_name}")
                    saved = analyzer.save(output_dir)
                    console.print(f"\n[green][+] LSB-поток сохранён:[/] {saved}")
                else:
                    # Показать размер без сохранения
                    lsb = analyzer.extract_lsb()
                    console.print(f"[dim]LSB: {len(lsb)} байт (не сохранено)[/]")
    except Exception as error:
        console.print(f"[red]Ошибка:[/] {error}")

    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
