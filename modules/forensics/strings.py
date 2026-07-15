from __future__ import annotations
import re

def extract_ascii_strings(data: bytes, min_length: int = 4) -> list[dict]:
    pattern = rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}"
    return [
        {
            "offset": match.start(),
            "offset_hex": hex(match.start()),
            "value": match.group().decode("ascii", errors="replace"),
        }
        for match in re.finditer(pattern, data)
    ]


def extract_utf16le_strings(data: bytes, min_length: int = 4) -> list[dict]:
    pattern = rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}"
    results = []
    for match in re.finditer(pattern, data):
        results.append(
            {
                "offset": match.start(),
                "offset_hex": hex(match.start()),
                "value": match.group().decode("utf-16le", errors="replace"),
            }
        )
    return results


def find_interesting_strings(strings: list[dict]) -> list[dict]:
    patterns = {
        "flag": r"(flag|ctf)\{[^}\s]{3,}\}",
        "url": r"https?://[^\s\"']+",
        "email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "ip": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "password_word": r"\b(pass|password|pwd|secret|token|key)\b",
    }
    results = []
    for item in strings:
        value = item["value"]
        for kind, pattern in patterns.items():
            if re.search(pattern, value, re.IGNORECASE):
                results.append({**item, "kind": kind})
    return results
