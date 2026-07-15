from __future__ import annotations

import math
import string

from .scoring import sort_results, text_score


LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase


def caesar_decrypt(data: str, shift: int) -> str:
    return _shift_text(data, -shift)


def caesar_bruteforce(data: str) -> list[dict]:
    results = []
    for shift in range(26):
        result = caesar_decrypt(data, shift)
        results.append({"method": "caesar", "shift": shift, "result": result, "score": text_score(result)})
    return sort_results(results)


def rot13_decode(data: str) -> str:
    return _shift_text(data, 13)


def rot47_decode(data: str) -> str:
    chars = []
    for ch in data:
        code = ord(ch)
        if 33 <= code <= 126:
            chars.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            chars.append(ch)
    return "".join(chars)


def atbash_decode(data: str) -> str:
    lower_map = str.maketrans(LOWER, LOWER[::-1])
    upper_map = str.maketrans(UPPER, UPPER[::-1])
    return data.translate(lower_map).translate(upper_map)


def vigenere_decrypt(data: str, key: str) -> str:
    if not key or not key.isalpha():
        raise ValueError("key must contain letters")
    result = []
    key_offsets = [ord(ch.lower()) - ord("a") for ch in key if ch.isalpha()]
    key_index = 0
    for ch in data:
        if ch.isalpha():
            alphabet = UPPER if ch.isupper() else LOWER
            offset = key_offsets[key_index % len(key_offsets)]
            result.append(alphabet[(alphabet.index(ch) - offset) % 26])
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


def vigenere_bruteforce(data: str, dictionary: list[str]) -> list[dict]:
    results = []
    for key in dictionary:
        try:
            result = vigenere_decrypt(data, key.strip())
        except ValueError:
            continue
        results.append({"method": "vigenere", "key": key.strip(), "result": result, "score": text_score(result)})
    return sort_results(results)


def affine_decrypt(data: str, key_a: int, key_b: int) -> str:
    if math.gcd(key_a, 26) != 1:
        raise ValueError("key_a must be coprime with 26")
    inverse = pow(key_a, -1, 26)
    result = []
    for ch in data:
        if ch.isalpha():
            alphabet = UPPER if ch.isupper() else LOWER
            x = alphabet.index(ch)
            result.append(alphabet[(inverse * (x - key_b)) % 26])
        else:
            result.append(ch)
    return "".join(result)


def affine_bruteforce(data: str) -> list[dict]:
    results = []
    for key_a in range(1, 26):
        if math.gcd(key_a, 26) != 1:
            continue
        for key_b in range(26):
            result = affine_decrypt(data, key_a, key_b)
            results.append({"method": "affine", "key_a": key_a, "key_b": key_b, "result": result, "score": text_score(result)})
    return sort_results(results)


def _shift_text(data: str, shift: int) -> str:
    result = []
    for ch in data:
        if ch in LOWER:
            result.append(LOWER[(LOWER.index(ch) + shift) % 26])
        elif ch in UPPER:
            result.append(UPPER[(UPPER.index(ch) + shift) % 26])
        else:
            result.append(ch)
    return "".join(result)
