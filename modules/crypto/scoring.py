from __future__ import annotations

import math
import re
import string
from typing import Any


COMMON_WORDS = (
    "the",
    "and",
    "that",
    "have",
    "for",
    "not",
    "with",
    "you",
    "this",
    "flag",
    "ctf",
    "key",
    "secret",
    "password",
    "hello",
    "world",
    "grodno",
)

COMMON_BIGRAMS = ("th", "he", "in", "er", "an", "re", "on", "at", "en", "nd")
EXPECTED_ENGLISH_FREQ = {
    "e": 12.70,
    "t": 9.06,
    "a": 8.17,
    "o": 7.51,
    "i": 6.97,
    "n": 6.75,
    "s": 6.33,
    "h": 6.09,
    "r": 5.99,
    "d": 4.25,
    "l": 4.03,
    "c": 2.78,
    "u": 2.76,
    "m": 2.41,
    "w": 2.36,
    "f": 2.23,
    "g": 2.02,
    "y": 1.97,
    "p": 1.93,
    "b": 1.49,
    "v": 0.98,
    "k": 0.77,
    "j": 0.15,
    "x": 0.15,
    "q": 0.10,
    "z": 0.07,
}


def _to_text(data: str | bytes) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def printable_ratio(data: str | bytes) -> float:
    text = _to_text(data)
    if not text:
        return 0.0
    allowed = set(string.printable) | set("\n\r\t")
    return sum(ch in allowed for ch in text) / len(text)


def language_score(text: str) -> float:
    if not text:
        return 0.0

    lowered = text.lower()
    letters = [ch for ch in lowered if "a" <= ch <= "z"]
    if not letters:
        return 0.0

    letter_ratio = len(letters) / max(len(text), 1)
    space_ratio = text.count(" ") / max(len(text), 1)
    word_hits = sum(1 for word in COMMON_WORDS if re.search(rf"\b{re.escape(word)}\b", lowered))
    bigram_hits = sum(lowered.count(pair) for pair in COMMON_BIGRAMS)

    counts = {ch: letters.count(ch) for ch in EXPECTED_ENGLISH_FREQ}
    chi_square = 0.0
    for ch, expected_pct in EXPECTED_ENGLISH_FREQ.items():
        expected = expected_pct * len(letters) / 100
        if expected:
            chi_square += (counts[ch] - expected) ** 2 / expected
    frequency_score = 1.0 / (1.0 + chi_square / 80.0)

    score = (
        0.40 * min(letter_ratio / 0.75, 1.0)
        + 0.25 * frequency_score
        + 0.15 * min(space_ratio / 0.18, 1.0)
        + 0.10 * min(word_hits / 3, 1.0)
        + 0.10 * min(bigram_hits / max(len(text) / 20, 1), 1.0)
    )
    return max(0.0, min(score, 1.0))


def flag_score(text: str, patterns: list[str] | None = None) -> float:
    if not text:
        return 0.0

    default_patterns = [
        r"flag\{[^}\s]{3,}\}",
        r"ctf\{[^}\s]{3,}\}",
        r"grodno\{[^}\s]{3,}\}",
        r"[a-z0-9_]{2,32}\{[^}\s]{3,}\}",
        r"\bflag[:=_-]?[a-z0-9_@#$%\-]{4,}\b",
    ]
    checks = patterns or default_patterns
    lowered = text.lower()
    hits = sum(1 for pattern in checks if re.search(pattern, lowered, re.IGNORECASE))
    return min(hits * 0.5, 1.0)


def text_score(data: str | bytes) -> float:
    text = _to_text(data)
    if not text:
        return 0.0

    printable = printable_ratio(text)
    language = language_score(text)
    flags = flag_score(text)
    control_count = sum(ord(ch) < 32 and ch not in "\n\r\t" for ch in text)
    replacement_count = text.count("\ufffd")
    garbage_penalty = min((control_count + replacement_count) / max(len(text), 1) * 2, 1.0)
    entropy = _entropy(text.encode("utf-8", errors="ignore"))
    entropy_penalty = max(0.0, min((entropy - 5.8) / 2.2, 1.0))

    score = 0.42 * printable + 0.34 * language + 0.20 * flags + 0.04 * (1.0 - entropy_penalty)
    return round(max(0.0, min(score - garbage_penalty * 0.35, 1.0)), 4)


def sort_results(results: list[dict]) -> list[dict]:
    return sorted(results, key=lambda item: float(item.get("score", 0.0)), reverse=True)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for value in set(data):
        probability = data.count(value) / length
        entropy -= probability * math.log2(probability)
    return entropy


def result_score_value(result: dict[str, Any]) -> float:
    return float(result.get("score", 0.0))
