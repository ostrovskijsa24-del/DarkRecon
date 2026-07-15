from __future__ import annotations
import math


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)
    for value in set(data):
        probability = data.count(value) / length
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def entropy_chunks(data: bytes, chunk_size: int = 1024) -> list[dict]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    chunks = []
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset : offset + chunk_size]
        chunks.append(
            {
                "offset": offset,
                "offset_hex": hex(offset),
                "size": len(chunk),
                "entropy": calculate_entropy(chunk),
            }
        )
    return chunks


def entropy_assessment(entropy: float) -> str:
    if entropy >= 7.5:
        return "high: возможно шифрование, сжатие или архив"
    if entropy >= 5.5:
        return "medium: смешанные или бинарные данные"
    return "low: похоже на текст или структурированные данные"
