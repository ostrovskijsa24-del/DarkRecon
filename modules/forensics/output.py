from __future__ import annotations

import json
from pathlib import Path

def print_summary(result: dict) -> None:
    print_feed(result)


def print_feed(result: dict, limit: int = 10) -> None:
    metadata = result.get("metadata", {})
    signature = result.get("signature", {})
    entropy = result.get("entropy", {})
    hashes = result.get("hashes", {})
    extension_check = result.get("extension_check", {})
    embedded_files = result.get("embedded_files", [])
    interesting = result.get("strings", {}).get("interesting", [])

    print("=== Анализ файла ===")
    print(f"Файл: {metadata.get('name', result.get('source'))}")
    print(f"Размер: {_format_size(metadata.get('size', 0))}")
    print(f"Тип: {signature.get('type', 'unknown')}")
    print(f"SHA256: {hashes.get('sha256')}")

    print("\n=== Проверки ===")
    print(f"Энтропия: {entropy.get('value')} - {entropy.get('assessment')}")
    if extension_check.get("checked"):
        status = "не совпадает" if extension_check.get("mismatch") else "совпадает"
        print(f"Расширение и сигнатура: {status}")
    else:
        print("Расширение и сигнатура: не проверялось")

    print("\n=== Находки ===")
    if embedded_files:
        print(f"Вложенные сигнатуры: {len(embedded_files)}")
        for item in embedded_files[:limit]:
            print(f"- {item['type']} на смещении {item['offset_hex']}")
        if len(embedded_files) > limit:
            print(f"- еще {len(embedded_files) - limit} скрыто в кратком выводе")
    else:
        print("Вложенные сигнатуры не найдены")

    if interesting:
        print("\n=== Интересные строки ===")
        for item in interesting[:limit]:
            print(f"- [{item['kind']}] {item['offset_hex']}: {_trim(item['value'])}")
        if len(interesting) > limit:
            print(f"- еще {len(interesting) - limit} скрыто в кратком выводе")
    else:
        print("\nИнтересные строки не найдены")


def print_full_report(result: dict) -> None:
    """Печатает полный отчет в консоль."""
    print(json.dumps(result, ensure_ascii=False, indent=2))


def save_report_json(result: dict, path: str) -> None:
    """Сохраняет отчет в JSON."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


def save_report_txt(result: dict, path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Forensics report",
        "================",
        f"source: {result.get('source')}",
        f"size: {result.get('metadata', {}).get('size')}",
        f"type: {result.get('signature', {}).get('type')}",
        f"entropy: {result.get('entropy', {}).get('value')}",
        f"md5: {result.get('hashes', {}).get('md5')}",
        f"sha256: {result.get('hashes', {}).get('sha256')}",
        f"embedded_files: {len(result.get('embedded_files', []))}",
        f"interesting_strings: {len(result.get('strings', {}).get('interesting', []))}",
    ]
    target.write_text("\n".join(lines), encoding="utf-8")


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


def _trim(text: str, limit: int = 120) -> str:
    clean = text.replace("\n", "\\n").replace("\r", "\\r")
    return clean if len(clean) <= limit else clean[: limit - 3] + "..."
