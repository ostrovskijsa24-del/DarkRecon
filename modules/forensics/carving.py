from __future__ import annotations
from .signatures import find_embedded_files

def find_file_markers(data: bytes) -> list[dict]:
    return find_embedded_files(data)


def carve_by_offsets(data: bytes, offsets: list[int]) -> list[dict]:
    sorted_offsets = sorted(set(offset for offset in offsets if 0 <= offset < len(data)))
    carved = []
    for index, offset in enumerate(sorted_offsets):
        end = sorted_offsets[index + 1] if index + 1 < len(sorted_offsets) else len(data)
        chunk = data[offset:end]
        carved.append(
            {
                "offset": offset,
                "offset_hex": hex(offset),
                "size": len(chunk),
                "preview_hex": chunk[:32].hex(),
            }
        )
    return carved
