from __future__ import annotations

import base64
import binascii
import math
import re
import string
import urllib.parse

from .decoders import MORSE_EN


def detect_encoding(data: str) -> list[str]:
    checks = [
        ("base64", is_base64),
        ("base32", is_base32),
        ("base85", is_base85),
        ("hex", is_hex),
        ("binary", is_binary),
        ("url", is_url_encoded),
        ("morse", is_morse),
    ]
    return [name for name, func in checks if func(data)]


def is_base64(data: str) -> bool:
    stripped = re.sub(r"\s+", "", data)
    if len(stripped) < 4 or len(stripped) % 4 != 0:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", stripped):
        return False
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return False
    return bool(decoded)


def is_base32(data: str) -> bool:
    stripped = re.sub(r"\s+", "", data).upper()
    if len(stripped) < 8 or len(stripped) % 8 != 0:
        return False
    if not re.fullmatch(r"[A-Z2-7]*={0,6}", stripped):
        return False
    try:
        decoded = base64.b32decode(stripped, casefold=True)
    except (binascii.Error, ValueError):
        return False
    return bool(decoded)


def is_base85(data: str) -> bool:
    stripped = data.strip()
    if len(stripped) < 5 or any(ch.isspace() for ch in stripped):
        return False
    if not all(33 <= ord(ch) <= 117 or ch in "yz" for ch in stripped):
        return False
    try:
        decoded = base64.b85decode(stripped)
    except (binascii.Error, ValueError):
        return False
    return bool(decoded)


def is_hex(data: str) -> bool:
    stripped = re.sub(r"[\s:,-]+", "", data)
    return len(stripped) >= 2 and len(stripped) % 2 == 0 and bool(re.fullmatch(r"[0-9a-fA-F]+", stripped))


def is_binary(data: str) -> bool:
    stripped = re.sub(r"\s+", "", data)
    return len(stripped) >= 8 and len(stripped) % 8 == 0 and bool(re.fullmatch(r"[01]+", stripped))


def is_url_encoded(data: str) -> bool:
    if not re.search(r"%[0-9a-fA-F]{2}", data):
        return False
    return urllib.parse.unquote(data) != data


MORSE_CHARS = set(".-/| ")


def is_morse(data: str) -> bool:
    stripped = data.strip()
    if len(stripped) < 3 or not set(stripped) <= MORSE_CHARS:
        return False
    tokens = [token for token in re.split(r"[ /|]+", stripped) if token]
    return bool(tokens) and all(token in MORSE_EN for token in tokens)


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for value in set(data):
        probability = data.count(value) / length
        entropy -= probability * math.log2(probability)
    return entropy


def detect_cipher(data: str) -> list[dict]:
    results: list[dict] = []
    text = data.strip()
    entropy = calculate_entropy(text.encode("utf-8", errors="ignore"))

    for encoding in detect_encoding(text):
        confidence = {
            "base64": 0.92,
            "base32": 0.90,
            "base85": 0.78,
            "hex": 0.88,
            "binary": 0.90,
            "url": 0.95,
            "morse": 0.86,
        }[encoding]
        results.append({"type": encoding, "confidence": confidence, "reason": "encoding pattern matched"})

    if re.fullmatch(r"(?:\d{1,3}[\s,;]+)*\d{1,3}", text):
        numbers = [int(item) for item in re.findall(r"\d{1,3}", text)]
        if numbers and all(0 <= number <= 255 for number in numbers):
            results.append({"type": "ascii_numbers", "confidence": 0.82, "reason": "byte-sized numeric sequence"})

    if re.search(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", text):
        results.append({"type": "unicode_escapes", "confidence": 0.93, "reason": "escape sequence pattern matched"})

    printable = sum(ch in string.printable for ch in text) / max(len(text), 1)
    if len(text) >= 8 and printable > 0.85 and any(ch.isalpha() for ch in text):
        results.append({"type": "caesar", "confidence": 0.35, "reason": "alphabetic printable text"})
        results.append({"type": "rot13", "confidence": 0.30, "reason": "alphabetic printable text"})
        results.append({"type": "atbash", "confidence": 0.25, "reason": "alphabetic printable text"})

    raw_candidates = ("hex", "base64", "base32", "base85", "binary")
    if entropy >= 3.5 or any(item["type"] in raw_candidates for item in results):
        results.append({"type": "single_byte_xor", "confidence": min(0.65, 0.25 + entropy / 12), "reason": "non-trivial entropy"})
        if len(text) >= 16:
            results.append({"type": "repeating_key_xor", "confidence": min(0.55, 0.20 + entropy / 14), "reason": "enough data for key-length analysis"})

    results.append({"type": "entropy", "confidence": round(min(entropy / 8, 1.0), 3), "entropy": round(entropy, 4)})
    return sorted(results, key=lambda item: float(item.get("confidence", 0.0)), reverse=True)
