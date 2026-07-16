"""
flags.py

Отбор кандидатов-флагов среди результатов криптоанализа.

Чистая бизнес-логика: ничего не печатает, только возвращает данные.
Вывод результатов — задача слоя tui (tui/reports_crypto.py).
"""
from __future__ import annotations

import re
from typing import Any


# Паттерны типичных CTF-флагов. Используются и для поиска, и для извлечения
# компактного представления кандидата.
FLAG_PATTERNS: tuple[str, ...] = (
    r"flag\{[^}\s]{3,}\}",
    r"ctf\{[^}\s]{3,}\}",
    r"[a-z0-9_]{2,32}\{[^}\s]{3,}\}",
    r"\bflag[:=_-]?[a-z0-9_@#$%\-]{4,}\b",
)


def extract_flag_match(text: str) -> str:
    """
    Возвращает первое совпадение с одним из FLAG_PATTERNS или пустую строку.
    """
    for pattern in FLAG_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(0)
    return ""


def extract_flag_candidate(text: str, max_length: int = 120) -> str:
    """
    Возвращает компактное представление кандидата: найденный флаг, либо
    укороченный (до max_length) текст с заменёнными переносами строк.
    """
    match = extract_flag_match(text)
    preview = match or text.replace("\n", "\\n")
    return _short_value(preview, max_length)


def select_probable_flags(results: list[dict], limit: int = 7) -> list[dict]:
    """
    Отбирает наиболее вероятные кандидаты-флаги.

    Сначала из результатов без ошибок берутся те, где реально найден флаг по
    шаблону; если таких нет — рассматриваются все читаемые результаты.
    Дубликаты по тексту кандидата отбрасываются; возвращается до ``limit`` штук.
    """
    clean_results = [
        result for result in results
        if not result.get("error") and str(result.get("result", "")).strip()
    ]
    flag_results = [
        result for result in clean_results
        if extract_flag_match(str(result.get("result", "")))
    ]
    selected = flag_results or clean_results

    unique: list[dict] = []
    seen: set[str] = set()
    for result in selected:
        key = extract_flag_candidate(str(result.get("result", ""))).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(result)
        if len(unique) == limit:
            break
    return unique


def _short_value(value: Any, max_length: int = 120) -> str:
    if isinstance(value, bytes):
        return value.hex()
    text = str(value)
    return text if len(text) <= max_length else text[: max_length - 3] + "..."
