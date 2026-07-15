from __future__ import annotations

import time
from pathlib import Path

from .carving import carve_by_offsets, find_file_markers
from .entropy import calculate_entropy, entropy_assessment, entropy_chunks
from .hashes import calculate_hashes
from .metadata import byte_distribution, file_metadata
from .signatures import check_extension_mismatch, detect_file_type
from .strings import extract_ascii_strings, extract_utf16le_strings, find_interesting_strings


def analyze_forensics(source: str | bytes | Path, chunk_size: int = 1024) -> dict:
    start = time.perf_counter()
    data, path = _load_source(source)

    signature = detect_file_type(data)
    ascii_strings = extract_ascii_strings(data)
    utf16_strings = extract_utf16le_strings(data)
    all_strings = ascii_strings + utf16_strings
    markers = find_file_markers(data)
    offsets = [item["offset"] for item in markers]
    entropy = calculate_entropy(data)

    result = {
        "source": str(path) if path else "<bytes>",
        "metadata": file_metadata(path) if path else {"size": len(data)},
        "signature": signature,
        "extension_check": check_extension_mismatch(str(path) if path else None, signature["type"]),
        "hashes": calculate_hashes(data),
        "entropy": {
            "value": entropy,
            "assessment": entropy_assessment(entropy),
            "chunks": entropy_chunks(data, chunk_size=chunk_size),
        },
        "byte_distribution": byte_distribution(data),
        "strings": {
            "ascii_count": len(ascii_strings),
            "utf16le_count": len(utf16_strings),
            "interesting": find_interesting_strings(all_strings),
            "all": all_strings,
        },
        "embedded_files": markers,
        "carved_preview": carve_by_offsets(data, offsets),
        "elapsed_seconds": round(time.perf_counter() - start, 6),
        "errors": [],
    }
    return result


def _load_source(source: str | bytes | Path) -> tuple[bytes, Path | None]:
    if isinstance(source, bytes):
        return source, None

    path = Path(source)
    return path.read_bytes(), path
