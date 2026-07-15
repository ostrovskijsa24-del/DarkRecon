from __future__ import annotations

from pathlib import Path


def file_metadata(path: str | Path) -> dict:
    target = Path(path)
    stat = target.stat()
    return {
        "path": str(target),
        "name": target.name,
        "extension": target.suffix.lower().lstrip("."),
        "size": stat.st_size,
        "created_time": stat.st_ctime,
        "modified_time": stat.st_mtime,
        "accessed_time": stat.st_atime,
    }


def byte_distribution(data: bytes) -> dict:
    if not data:
        return {"unique_bytes": 0, "null_bytes": 0, "null_ratio": 0.0}

    null_bytes = data.count(0)
    return {
        "unique_bytes": len(set(data)),
        "null_bytes": null_bytes,
        "null_ratio": round(null_bytes / len(data), 4),
    }
