from __future__ import annotations

from .scoring import sort_results, text_score


def xor_with_key(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("key must not be empty")
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def single_byte_xor(data: bytes, key: int) -> bytes:
    if not 0 <= key <= 255:
        raise ValueError("key must be in range 0..255")
    return bytes(byte ^ key for byte in data)


def single_byte_xor_bruteforce(data: bytes) -> list[dict]:
    results = []
    for key in range(256):
        result = single_byte_xor(data, key)
        results.append({"method": "single_byte_xor", "key": key, "result": result, "score": text_score(result)})
    return sort_results(results)


def repeating_key_xor(data: bytes, key: bytes) -> bytes:
    return xor_with_key(data, key)


def detect_xor_key_length(data: bytes, min_length: int = 2, max_length: int = 40) -> list[int]:
    scores = []
    upper = min(max_length, max(min_length, len(data) // 2))
    for key_size in range(min_length, upper + 1):
        chunks = [data[index : index + key_size] for index in range(0, key_size * 8, key_size)]
        chunks = [chunk for chunk in chunks if len(chunk) == key_size]
        if len(chunks) < 2:
            continue
        distances = []
        for left, right in zip(chunks, chunks[1:]):
            distances.append(_hamming_distance(left, right) / key_size)
        if distances:
            scores.append((sum(distances) / len(distances), key_size))
    return [key_size for _, key_size in sorted(scores)[:5]]


def repeating_key_xor_bruteforce(data: bytes) -> list[dict]:
    results = []
    for key_length in detect_xor_key_length(data):
        key_bytes = []
        for offset in range(key_length):
            block = data[offset::key_length]
            best = single_byte_xor_bruteforce(block)[0]
            key_bytes.append(best["key"])
        key = bytes(key_bytes)
        result = repeating_key_xor(data, key)
        results.append({"method": "repeating_key_xor", "key": key, "key_length": key_length, "result": result, "score": text_score(result)})
    return sort_results(results)


def xor_known_plaintext(ciphertext: bytes, known_text: bytes, offset: int = 0) -> bytes:
    if offset < 0:
        raise ValueError("offset must be non-negative")
    if offset + len(known_text) > len(ciphertext):
        raise ValueError("known plaintext exceeds ciphertext length at offset")
    return bytes(ciphertext[offset + index] ^ byte for index, byte in enumerate(known_text))


def _hamming_distance(left: bytes, right: bytes) -> int:
    if len(left) != len(right):
        raise ValueError("inputs must have equal length")
    return sum((a ^ b).bit_count() for a, b in zip(left, right))
