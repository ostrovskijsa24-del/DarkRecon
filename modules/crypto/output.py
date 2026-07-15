
from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Any


FLAG_PATTERNS = (
    r"flag\{[^}\s]{3,}\}",
    r"ctf\{[^}\s]{3,}\}",
    r"[a-z0-9_]{2,32}\{[^}\s]{3,}\}",
    r"\bflag[:=_-]?[a-z0-9_@#$%\-]{4,}\b",
)


def print_probable_flags(results: list[dict], limit: int = 7) -> None:
    selected = _select_probable_flags(results, limit)
    if not selected:
        print("Подходящих кандидатов не найдено.")
        return

    for number, result in enumerate(selected, start=1):
        print(format_compact_result(result, number))


def print_results(results: list[dict], limit: int | None = None) -> None:
    selected = results[:limit] if limit is not None else results
    for number, result in enumerate(selected, start=1):
        print_result(result, number)


def print_result(result: dict, number: int) -> None:
    print(format_result(result, number))


def format_result(result: dict, number: int | None = None) -> str:
    prefix = f"{number}. " if number is not None else ""
    method = result.get("method", "unknown")
    score = float(result.get("score", 0.0))
    chain = " -> ".join(result.get("chain", [])) or method
    error = result.get("error")
    params = _format_params(result.get("parameters", {}))
    if error:
        return f"{prefix}[{score:.4f}] {method} ({chain}) ERROR: {error}"

    text = str(result.get("result", ""))
    preview = text.replace("\n", "\\n")
    if len(preview) > 240:
        preview = preview[:237] + "..."
    suffix = f" params={params}" if params else ""
    return f"{prefix}[{score:.4f}] {method} ({chain}){suffix}: {preview}"


def format_compact_result(result: dict, number: int | None = None) -> str:
    prefix = f"{number}. " if number is not None else ""
    score = float(result.get("score", 0.0))
    chain = " -> ".join(result.get("chain", [])) or result.get("method", "unknown")
    candidate = _extract_flag_candidate(str(result.get("result", "")))
    return f"{prefix}[{score:.4f}] {chain}: {candidate}"


def save_results_txt(results: list[dict], path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = ["Crypto analysis report", "=" * 22, ""]
    for number, result in enumerate(results, start=1):
        lines.append(format_result(result, number))
        lines.append(f"depth: {result.get('depth')}")
        lines.append(f"elapsed_seconds: {result.get('elapsed_seconds')}")
        lines.append(f"result_bytes_hex: {result.get('result_bytes_hex')}")
        lines.append("")
    target.write_text("\n".join(lines), encoding="utf-8")


def save_results_json(results: list[dict], path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(_json_ready(results), ensure_ascii=False, indent=2), encoding="utf-8")


def save_report(results: list[dict], directory: str = "results") -> None:
    target_dir = Path(directory)
    save_results_json(results, str(target_dir / "report.json"))
    save_results_txt(results, str(target_dir / "report.txt"))


def _format_params(parameters: dict[str, Any]) -> str:
    if not parameters:
        return ""
    return ", ".join(f"{key}={_short_value(value)}" for key, value in parameters.items())


def _select_probable_flags(results: list[dict], limit: int) -> list[dict]:
    clean_results = [result for result in results if not result.get("error") and str(result.get("result", "")).strip()]
    flag_results = [result for result in clean_results if _extract_flag_match(str(result.get("result", "")))]
    selected = flag_results or clean_results
    unique: list[dict] = []
    seen: set[str] = set()
    for result in selected:
        key = _extract_flag_candidate(str(result.get("result", ""))).lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(result)
        if len(unique) == limit:
            break
    return unique


def _extract_flag_candidate(text: str) -> str:
    match = _extract_flag_match(text)
    preview = match or text.replace("\n", "\\n")
    return _short_value(preview)


def _extract_flag_match(text: str) -> str:
    for pattern in FLAG_PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(0)
    return ""


def _short_value(value: Any) -> str:
    if isinstance(value, bytes):
        return value.hex()
    text = str(value)
    return text if len(text) <= 120 else text[:117] + "..."


def _json_ready(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value
