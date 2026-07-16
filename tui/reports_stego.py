"""
Вывод отчётов модуля Stego.

Чистая презентация: рисует результаты стегоанализа через rich.
Данные формируют бизнес-классы из modules.stego.*.
"""
from __future__ import annotations

from . import console


# ═════════════ Statistics ═════════════

def print_statistics(report: dict) -> None:
    """Выводит отчёт статистического анализа изображения."""
    console.print("\n[bold cyan]══════ IMAGE STATISTICS ══════[/]")
    console.print(f"[bold]Image    :[/] {report['image']}")
    console.print(f"[bold]Size     :[/] {report['width']} × {report['height']}")
    console.print(f"[bold]Channels :[/] {report['channels']}\n")

    for item in report["results"]:
        lsb_status = (
            "[bold red]Suspicious[/]" if item["status"] == "Suspicious"
            else "[green]Normal[/]"
        )
        console.print(f"  [[cyan]{item['channel']}[/]]")
        console.print(f"    Entropy : {item['entropy']:.4f}")
        console.print(f"    Mean    : {item['mean']:.2f}")
        console.print(f"    Std Dev : {item['std']:.2f}")
        console.print(f"    LSB 1's : {item['lsb']:.2f}%   {lsb_status}")
        console.print()


# ═════════════ Palette ═════════════

def print_palette(report: dict) -> None:
    """Выводит отчёт анализа палитры PNG."""
    console.print("\n[bold cyan]══════ PNG PALETTE ANALYSIS ══════[/]")
    console.print(f"[bold]Image:[/] {report['image']}")

    if not report["has_palette"]:
        console.print("\n[dim]Палитра отсутствует (RGB/RGBA).[/]")
        return

    console.print(f"[bold]Palette          :[/] Yes")
    console.print(f"[bold]Colors           :[/] {report['palette_size']}")
    console.print(f"[bold]Unique colors    :[/] {report['unique_colors']}")
    console.print(f"[bold]Duplicate colors :[/] {report['duplicated_colors']}")

    status = (
        "[bold red]Suspicious[/]" if report["status"] == "Suspicious"
        else "[green]Normal[/]"
    )
    console.print(f"[bold]Status           :[/] {status}")


# ═════════════ PNG structure ═════════════

def print_png_structure(report: dict) -> None:
    """Выводит отчёт структуры PNG: чанки, неизвестные, оверлей."""
    console.print("\n[bold cyan]══════ PNG STRUCTURE ══════[/]")
    console.print(f"[bold]File :[/] {report['file']}\n")

    console.print("[bold]Chunks:[/]")
    known_set = {
        "IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "gAMA",
        "pHYs", "sRGB", "cHRM", "bKGD", "hIST", "sBIT", "tIME", "tRNS",
    }
    for index, chunk in enumerate(report["chunks"], start=1):
        is_known = chunk["type"] in known_set
        tag = "[dim]Standard[/]" if is_known else "[bold yellow]Unknown[/]"
        console.print(
            f"  {index:2}. [cyan]{chunk['type']:<5}[/] "
            f"{chunk['length']:>8} bytes   {tag}"
        )

    console.print()
    if report["unknown"]:
        console.print(f"[bold yellow]Unknown chunks:[/] {len(report['unknown'])}")
        for chunk in report["unknown"]:
            console.print(f"  • [yellow]{chunk['type']}[/] ({chunk['length']} bytes)")
    else:
        console.print("[green]Unknown chunks: none[/]")

    overlay = (
        "[bold red]YES[/]" if report["overlay"] else "[green]NO[/]"
    )
    console.print(f"\n[bold]Overlay after IEND:[/] {overlay}")


# ═════════════ Audio ═════════════

def print_audio_info(info: dict) -> None:
    """Выводит информацию о WAV-файле."""
    console.print("\n[bold cyan]══════ AUDIO INFO ══════[/]")
    console.print(f"[bold]File         :[/] {info['filename']}")
    console.print(f"[bold]Channels     :[/] {info['channels']}")
    console.print(f"[bold]Sample Width :[/] {info['sample_width']} bytes")
    console.print(f"[bold]Sample Rate  :[/] {info['frame_rate']} Hz")
    console.print(f"[bold]Frames       :[/] {info['frames']}")
    console.print(f"[bold]Compression  :[/] {info['compression']}")


# ═════════════ Общий прогресс сохранения ═════════════

def print_saved_files(paths: list, label: str = "Сохранено") -> None:
    """Показывает список сохранённых файлов."""
    console.print(f"\n[green][+][/] {label}: {len(paths)} файл(ов)")
    for p in paths[:15]:
        console.print(f"    • {p}")
    if len(paths) > 15:
        console.print(f"    [dim]… и ещё {len(paths) - 15}[/]")
