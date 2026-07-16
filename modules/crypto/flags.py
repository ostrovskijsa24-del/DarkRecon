"""
flags.py

Отбор кандидатов-флагов среди результатов криптоанализа.
Чистая бизнес-логика: ничего не печатает, только возвращает данные.
"""
from __future__ import annotations

import re
from typing import Any

DEFAULT_PATTERNS = [
    r"\b[a-z0-9_]{0,32}(?:ctf|flag)\{[^}\s]{3,}\}",
    r"[a-z0-9_]{2,32}\{[^}\s]{3,}\}",
    r"\bflag[:=_-]?[a-z0-9_@#$%\-]{4,}\b",
]

def get_patterns(custom_prefix: str = "") -> list[str]:
    """Генерирует список регулярок. Если есть префикс, ставит его первым."""
    if not custom_prefix:
        return DEFAULT_PATTERNS
    
    # Если пользователь ввел готовую регулярку (содержит скобку)
    if "{" in custom_prefix or r"\{" in custom_prefix:
        return [custom_prefix] + DEFAULT_PATTERNS
        
    # Иначе строим стандартный паттерн поиска: prefix{...}
    custom_pattern = rf"(?i)\b{re.escape(custom_prefix)}\{{[^}}\s]+\}}"
    return [custom_pattern] + DEFAULT_PATTERNS


def extract_flag_match(text: str, patterns: list[str]) -> str:
    """Ищет совпадение по списку паттернов."""
    for pattern in patterns:
        try:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        except re.error:
            continue
    return ""


def split_probable_results(results: list[dict], limit: int, custom_prefix: str = "") -> tuple[list[dict], list[dict]]:
    """Разделяет результаты на Топ-N лучших и все остальные."""
    patterns = get_patterns(custom_prefix)
    
    clean_results = [r for r in results if not r.get("error") and str(r.get("result", "")).strip()]
    flag_results = [r for r in clean_results if extract_flag_match(str(r.get("result", "")), patterns)]
    
    # Сначала идут те, где флаг точно найден, потом остальные читаемые
    if flag_results:
        flag_ids = {id(r) for r in flag_results}
        candidates = flag_results + [r for r in clean_results if id(r) not in flag_ids]
    else:
        candidates = clean_results

    unique: list[dict] = []
    seen: set[str] = set()
    
    for result in candidates:
        text = str(result.get("result", ""))
        match = extract_flag_match(text, patterns)
        preview = match or text.replace("\n", "\\n")
        key = (preview if len(preview) <= 120 else preview[:117] + "...").lower()
        
        if key not in seen:
            seen.add(key)
            if len(unique) < limit:
                unique.append(result)

    selected_ids = {id(r) for r in unique}
    remaining = [r for r in results if id(r) not in selected_ids]
    
    return unique, remaining