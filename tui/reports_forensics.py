"""
Вывод отчётов модуля Forensics.

Чистая презентация:
- Рисует красивый краткий отчет в консоли через rich.
- Форматирует и записывает полный детальный отчет в plain-text файл.
"""
from __future__ import annotations

from pathlib import Path
from . import console


# ─── ГЛАВНАЯ ТОЧКА ВХОДА ИНТЕРФЕЙСА ─────────────────────────────────

def print_and_save_forensics_report(result: dict, output_path: Path, limit: int = 10) -> None:
    """Сохраняет полный отчет в текстовый файл и выводит краткое саммари в консоль."""
    # 1. Сохраняем полный детальный отчет на диск
    _save_report_txt(result, output_path)

    # 2. Выводим краткий красивый отчет в консоль (Саммари)
    metadata = result.get("metadata", {})
    signature = result.get("signature", {})
    entropy = result.get("entropy", {})
    hashes = result.get("hashes", {})
    extension_check = result.get("extension_check", {})
    embedded_files = result.get("embedded_files", [])
    interesting = result.get("strings", {}).get("interesting", [])

    console.print("\n[bold cyan]═══ Анализ файла (Кратко) ═══[/]")
    console.print(f"[bold]Файл:[/] {metadata.get('name', result.get('source'))}")
    console.print(f"[bold]Размер:[/] {_format_size(metadata.get('size', 0))}")
    console.print(f"[bold]Тип:[/] [yellow]{_format_file_type(signature.get('type'))}[/]")
    console.print(f"[bold]SHA256:[/] [dim]{hashes.get('sha256')}[/]")

    console.print("\n[bold]═══ Проверки ═══[/]")
    console.print(
        f"[bold]Энтропия:[/] {entropy.get('value')} — {entropy.get('assessment')}"
    )
    if extension_check.get("checked"):
        status = (
            "[red]НЕ СОВПАДАЕТ[/]" if extension_check.get("mismatch")
            else "[green]совпадает[/]"
        )
        console.print(f"[bold]Расширение и сигнатура:[/] {status}")
    else:
        console.print("[bold]Расширение и сигнатура:[/] [dim]не проверялось[/]")

    console.print("\n[bold]═══ Находки ═══[/]")
    if embedded_files:
        console.print(f"[bold]Вложенные сигнатуры:[/] {len(embedded_files)}")
        for item in embedded_files[:limit]:
            console.print(f"  • [yellow]{_format_file_type(item.get('type'))}[/] на смещении {item.get('offset_hex')}")
        if len(embedded_files) > limit:
            console.print(f"  [dim]… ещё {len(embedded_files) - limit} скрыто в кратком выводе[/]")
    else:
        console.print("[dim]Вложенные сигнатуры не найдены[/]")

    if interesting:
        console.print("\n[bold]═══ Интересные строки ═══[/]")
        for item in interesting[:limit]:
            console.print(
                f"  • [[yellow]{item.get('kind')}[/]] {item.get('offset_hex')}: "
                f"{_trim(item.get('value', ''))}"
            )
        if len(interesting) > limit:
            console.print(f"  [dim]… ещё {len(interesting) - limit} скрыто в кратком выводе[/]")
    else:
        console.print("[dim]Интересные строки не найдены[/]")

    console.print(f"\n[green][+][/] Полный детальный отчет успешно сохранен в: [yellow]{output_path}[/]")


# ─── СБОРКА И ЗАПИСЬ ПОЛНОГО ТЕКСТОВОГО ОТЧЕТА (БЕЗ ЦВЕТОВ) ────────

def _save_report_txt(result: dict, path: Path) -> None:
    """Записывает полный детальный отчет в plain-text файл."""
    path.parent.mkdir(parents=True, exist_ok=True)
    
    metadata = result.get("metadata", {})
    signature = result.get("signature", {})
    entropy = result.get("entropy", {})
    entropy_chunks = entropy.get("chunks", [])
    hashes = result.get("hashes", {})
    extension_check = result.get("extension_check", {})
    byte_distribution = result.get("byte_distribution", {})
    embedded_files = result.get("embedded_files", [])
    carved_preview = result.get("carved_preview", [])
    strings = result.get("strings", {})
    interesting = result.get("strings", {}).get("interesting", [])
    all_strings = strings.get("all", [])
    errors = result.get("errors", [])

    lines = [
        "=== FORENSICS: ПОЛНЫЙ АНАЛИЗ ФАЙЛА ===",
        f"Источник: {result.get('source')}",
        "=== ТИП И СИГНАТУРА ===",
        f"Тип: {_format_file_type(signature.get('type', 'unknown'))}",
        f"Сигнатура: {signature.get('signature_hex') or '-'}",
        f"Уверенность: {signature.get('confidence', 0)}",
    ]

    if extension_check.get("checked"):
        status = "НЕ СОВПАДАЕТ" if extension_check.get("mismatch") else "совпадает"
        lines.extend([
            f"Расширение файла: {extension_check.get('extension') or '-'}",
            f"Тип по сигнатуре: {_format_file_type(extension_check.get('detected_type') or '-')}",
            f"Расширение и сигнатура: {status}",
        ])
    else:
        lines.append("Расширение и сигнатура: не проверялось")

    lines.extend([
        "",
        "=== ХЕШИ ===",
        f"MD5: {hashes.get('md5') or '-'}",
        f"SHA1: {hashes.get('sha1') or '-'}",
        f"SHA256: {hashes.get('sha256') or '-'}",
        f"CRC32: {hashes.get('crc32') or '-'}",
        "",
        "=== ЭНТРОПИЯ ===",
        f"Общая энтропия: {entropy.get('value')} - {entropy.get('assessment')}",
    ])

    if entropy_chunks:
        lines.append(f"Чанки энтропии: {len(entropy_chunks)}")
        high_entropy_chunks = [item for item in entropy_chunks if float(item.get("entropy", 0.0)) >= 7.5]
        if high_entropy_chunks:
            lines.append("Чанки с высокой энтропией:")
            for item in high_entropy_chunks[:10]:
                lines.append(
                    f"- {item.get('offset_hex')} | размер: {_format_size(item.get('size', 0))} | "
                    f"энтропия: {item.get('entropy')}"
                )
            if len(high_entropy_chunks) > 10:
                lines.append(f"- еще {len(high_entropy_chunks) - 10} высокоэнтропийных чанков скрыто")
        else:
            lines.append("Чанков с высокой энтропией не найдено")
    else:
        lines.append("Чанки энтропии: не найдены")

    lines.extend([
        "",
        "=== РАСПРЕДЕЛЕНИЕ БАЙТОВ ===",
        f"Уникальных байтов: {byte_distribution.get('unique_bytes', 0)}",
        f"Нулевых байтов: {byte_distribution.get('null_bytes', 0)}",
        f"Доля нулевых байтов: {byte_distribution.get('null_ratio', 0.0)}",
        "",
        "=== ВЛОЖЕННЫЕ СИГНАТУРЫ ===",
    ])

    if embedded_files:
        lines.append(f"Найдено: {len(embedded_files)}")
        for item in embedded_files:
            lines.append(
                f"- {_format_file_type(item.get('type'))} | смещение: {item.get('offset_hex')} | "
                f"сигнатура: {item.get('signature_hex')}"
            )
    else:
        lines.append("Не найдены")

    lines.extend(["", "=== CARVED PREVIEW ==="])
    if carved_preview:
        lines.append(f"Фрагментов: {len(carved_preview)}")
        for item in carved_preview:
            lines.append(
                f"- смещение: {item.get('offset_hex')} | размер: {_format_size(item.get('size', 0))} | "
                f"preview_hex: {item.get('preview_hex')}"
            )
    else:
        lines.append("Фрагменты для карвинга не найдены")

    lines.extend([
        "",
        "=== СТРОКИ ===",
        f"ASCII строк: {strings.get('ascii_count', 0)}",
        f"UTF-16LE строк: {strings.get('utf16le_count', 0)}",
        f"Интересных строк: {len(interesting)}",
        "",
        "=== ИНТЕРЕСНЫЕ СТРОКИ ===",
    ])

    if interesting:
        for item in interesting:
            lines.append(f"- [{item.get('kind')}] {item.get('offset_hex')}: {_trim(item.get('value', ''))}")
    else:
        lines.append("Не найдены")

    lines.extend(["", "=== ВСЕ ИЗВЛЕЧЕННЫЕ СТРОКИ ==="])
    if all_strings:
        for item in all_strings:
            lines.append(f"- {item.get('offset_hex')}: {_trim(item.get('value', ''))}")
    else:
        lines.append("Строки не найдены")

    if errors:
        lines.extend(["", "=== ОШИБКИ ==="])
        for error in errors:
            lines.append(f"- {error}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ─── ВСПОМОГАТЕЛЬНЫЕ УТИЛИТЫ ФОРМАТИРОВАНИЯ ────────────────────────

def _format_size(size: int | None) -> str:
    if not size:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def _format_file_type(file_type: str | None) -> str:
    labels = {
        "unknown": "неизвестный",
        "png": "PNG image",
        "jpg": "JPEG image",
        "gif": "GIF image",
        "pdf": "PDF document",
        "zip": "ZIP archive",
        "zip_empty": "empty ZIP archive",
        "zip_spanned": "spanned ZIP archive",
        "rar": "RAR archive",
        "7z": "7z archive",
        "gzip": "GZip archive",
        "bzip2": "BZip2 archive",
        "xz": "XZ archive",
        "sqlite": "SQLite database",
        "pe_executable": "Windows executable (PE/MZ)",
        "elf": "Linux executable (ELF)",
        "mp3": "MP3 audio",
        "ogg": "OGG audio",
        "riff": "RIFF container",
        "ico": "ICO image",
        "cur": "CUR cursor",
        "bmp": "BMP image",
        "mp4_mov": "MP4/MOV video",
    }
    return labels.get(file_type or "unknown", str(file_type))


def _trim(text: str, limit: int = 120) -> str:
    clean = text.replace("\n", "\\n").replace("\r", "\\r")
    return clean if len(clean) <= limit else clean[: limit - 3] + "..."