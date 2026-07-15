from __future__ import annotations

FILE_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip_empty"),
    (b"PK\x07\x08", "zip_spanned"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"MZ", "pe_executable"),
    (b"\x7fELF", "elf"),
    (b"ID3", "mp3"),
    (b"\xff\xfb", "mp3"),
    (b"OggS", "ogg"),
    (b"RIFF", "riff"),
    (b"\x00\x00\x01\x00", "ico"),
    (b"\x00\x00\x02\x00", "cur"),
    (b"BM", "bmp"),
]


def detect_file_type(data: bytes) -> dict:
    for signature, file_type in FILE_SIGNATURES:
        if data.startswith(signature):
            return {
                "type": file_type,
                "signature_hex": signature.hex(),
                "confidence": 0.95,
            }

    if len(data) >= 12 and data[4:8] == b"ftyp":
        return {"type": "mp4_mov", "signature_hex": data[:12].hex(), "confidence": 0.90}

    return {"type": "unknown", "signature_hex": data[:16].hex(), "confidence": 0.0}


def find_embedded_files(data: bytes) -> list[dict]:
    results: list[dict] = []
    for signature, file_type in FILE_SIGNATURES:
        start = 0
        while True:
            offset = data.find(signature, start)
            if offset == -1:
                break
            results.append(
                {
                    "type": file_type,
                    "offset": offset,
                    "offset_hex": hex(offset),
                    "signature_hex": signature.hex(),
                }
            )
            start = offset + 1
    return sorted(results, key=lambda item: item["offset"])


def check_extension_mismatch(path: str | None, detected_type: str) -> dict:
    if not path:
        return {"checked": False, "mismatch": False}

    extension = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    aliases = {
        "jpg": {"jpg", "jpeg"},
        "zip": {"zip", "docx", "xlsx", "pptx", "jar", "apk"},
        "mp4_mov": {"mp4", "mov", "m4v"},
        "pe_executable": {"exe", "dll"},
    }
    valid_extensions = aliases.get(detected_type, {detected_type})
    mismatch = bool(extension and detected_type != "unknown" and extension not in valid_extensions)
    return {
        "checked": True,
        "extension": extension,
        "detected_type": detected_type,
        "mismatch": mismatch,
    }
