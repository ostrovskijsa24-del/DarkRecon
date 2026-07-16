"""
Запуск модулей Stego.

Каждый раннер запрашивает путь к файлу (ручной ввод или системный
диалог), создаёт соответствующий класс-анализатор из modules.stego
и вызывает его точку входа. Вывод модулей (plain print) не меняется.
"""
from __future__ import annotations

from rich.prompt import Prompt, Confirm

from . import console

from modules.stego.bitplanes import BitPlaneAnalyzer
from modules.stego.combine_planes import PlaneCombiner
from modules.stego.xor_planes import XorPlaneAnalyzer
from modules.stego.statistics import StatisticsAnalyzer
from modules.stego.palette import PaletteAnalyzer
from modules.stego.png_structure import PNGStructureAnalyzer
from modules.stego.audio import AudioAnalyzer
from modules.stego.file_dialog import FileDialog


def _ask_path(kind: str = "файл") -> str | None:
    """
    Запрос пути к файлу: ручной ввод через rich или системный диалог.

    Возвращает путь или None, если пользователь отменил ввод.
    Системный диалог требует графическое окружение (tkinter); если его нет —
    предлагается ручной ввод.
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


def _run(kind: str, factory):
    """
    Общий каркас: запрос пути -> создание анализатора -> вызов точки входа.
    `factory` принимает путь и возвращает экземпляр анализатора.
    """
    path = _ask_path(kind)
    if not path:
        console.print("[red]Путь не указан[/]")
        Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")
        return
    try:
        analyzer = factory(path)
        # Все stego-анализаторы выводят результат через plain print.
        if hasattr(analyzer, "extract_all"):
            analyzer.extract_all()
        else:
            analyzer.run()
    except Exception as error:
        console.print(f"[red]Ошибка:[/] {error}")
    Prompt.ask("\n[dim]Enter, чтобы продолжить[/]")


def run_bitplanes():
    console.print("\n[bold cyan]═══ БИТОВЫЕ ПЛОСКОСТИ ═══[/]")
    console.print("[dim]Извлекает битовые плоскости каждого канала изображения[/]")
    console.print("[dim](полезно для визуального поиска LSB-стеганографии).[/]")
    _run("изображению", lambda p: BitPlaneAnalyzer(p))


def run_combine():
    console.print("\n[bold cyan]═══ ОБЪЕДИНЕНИЕ ПЛОСКОСТЕЙ ═══[/]")
    console.print("[dim]Собирает изображение из выбранных битовых плоскостей[/]")
    console.print("[dim](например, младшие биты — потенциально скрытое сообщение).[/]")
    _run("изображению", lambda p: PlaneCombiner(p))


def run_xor():
    console.print("\n[bold cyan]═══ XOR ПЛОСКОСТЕЙ ═══[/]")
    console.print("[dim]XOR-анализ битовых плоскостей для выявления скрытых данных.[/]")
    _run("изображению", lambda p: XorPlaneAnalyzer(p))


def run_statistics():
    console.print("\n[bold cyan]═══ СТАТИСТИКА ИЗОБРАЖЕНИЯ ═══[/]")
    console.print("[dim]Гистограммы и статистика распределения пикселей[/]")
    console.print("[dim](аномалии могут указывать на встроенные данные).[/]")
    _run("изображению", lambda p: StatisticsAnalyzer(p))


def run_palette():
    console.print("\n[bold cyan]═══ АНАЛИЗ ПАЛИТРЫ ═══[/]")
    console.print("[dim]Анализ палитры PNG (скрытые/неиспользуемые цвета, аномалии).[/]")
    _run("PNG", lambda p: PaletteAnalyzer(p))


def run_png_structure():
    console.print("\n[bold cyan]═══ СТРУКТУРА PNG ═══[/]")
    console.print("[dim]Разбор чанков PNG, поиск скрытых данных после IEND[/]")
    console.print("[dim]или в нестандартных/повторных чанках.[/]")
    _run("PNG", lambda p: PNGStructureAnalyzer(p))


def run_audio():
    console.print("\n[bold cyan]═══ АНАЛИЗ АУДИО (WAV) ═══[/]")
    console.print("[dim]LSB в сэмплах, метаданные и спектрограмма аудиофайла.[/]")
    _run("WAV", lambda p: AudioAnalyzer(p))
