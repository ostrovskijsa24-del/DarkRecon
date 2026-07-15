from __future__ import annotations

import hashlib
import zlib


def calculate_hashes(data: bytes) -> dict:
    """Считает основные хэши файла."""
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "crc32": f"{zlib.crc32(data) & 0xFFFFFFFF:08x}",
    }
