from __future__ import annotations

import time
from typing import Any

from .classical_ciphers import affine_bruteforce, atbash_decode, caesar_bruteforce, rot13_decode, rot47_decode
from .decoders import DECODERS, decode_by_type
from .detector import detect_cipher
from .scoring import sort_results, text_score
from .xor import repeating_key_xor_bruteforce, single_byte_xor_bruteforce


def analyze_crypto(data: str | bytes, recursive: bool = True, max_depth: int = 3) -> list[dict]:
    start_time = time.perf_counter()
    seen: set[tuple[str, int]] = set()
    all_results: list[dict] = []

    def walk(current: str | bytes, depth: int, chain: list[str]) -> None:
        normalized_text = _to_text(current)
        raw = _to_bytes(current)
        marker = (normalized_text, depth)
        if marker in seen or depth > max_depth:
            return
        seen.add(marker)

        detections = detect_cipher(normalized_text)
        all_results.append(
            _make_result(
                method="input",
                result=current,
                score=text_score(current),
                depth=depth,
                chain=chain,
                parameters={"detections": detections},
                started_at=start_time,
            )
        )

        for detection in detections:
            encoding_type = detection["type"]
            if encoding_type not in DECODERS:
                continue
            try:
                decoded = decode_by_type(normalized_text, encoding_type)
                result = _make_result(
                    method=encoding_type,
                    result=decoded,
                    score=text_score(decoded),
                    depth=depth,
                    chain=chain + [encoding_type],
                    parameters={"confidence": detection.get("confidence")},
                    started_at=start_time,
                )
                all_results.append(result)
                if recursive and depth < max_depth and _is_promising(decoded):
                    walk(decoded, depth + 1, chain + [encoding_type])
            except Exception as error:  
                all_results.append(_error_result(encoding_type, error, depth, chain, start_time))

        for item in caesar_bruteforce(normalized_text)[:26]:
            all_results.append(_from_candidate(item, depth, chain + ["caesar"], start_time))

        for method, decoded in (
            ("rot13", rot13_decode(normalized_text)),
            ("rot47", rot47_decode(normalized_text)),
            ("atbash", atbash_decode(normalized_text)),
        ):
            all_results.append(
                _make_result(method, decoded, text_score(decoded), depth, chain + [method], {}, start_time)
            )

        for item in affine_bruteforce(normalized_text)[:20]:
            all_results.append(_from_candidate(item, depth, chain + ["affine"], start_time))

        if raw:
            for item in single_byte_xor_bruteforce(raw)[:20]:
                all_results.append(_from_candidate(item, depth, chain + ["single_byte_xor"], start_time))
            if len(raw) >= 16:
                for item in repeating_key_xor_bruteforce(raw)[:10]:
                    all_results.append(_from_candidate(item, depth, chain + ["repeating_key_xor"], start_time))

    walk(data, 0, [])
    return sort_results(_deduplicate(all_results))


def _to_text(data: str | bytes) -> str:
    return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data


def _to_bytes(data: str | bytes) -> bytes:
    return data if isinstance(data, bytes) else data.encode("utf-8", errors="ignore")


def _is_promising(data: str | bytes) -> bool:
    text = _to_text(data)
    return bool(text.strip()) and len(text) <= 20000 and text_score(text) >= 0.25


def _make_result(
    method: str,
    result: str | bytes,
    score: float,
    depth: int,
    chain: list[str],
    parameters: dict[str, Any],
    started_at: float,
) -> dict:
    text = _to_text(result)
    return {
        "method": method,
        "result": text,
        "result_bytes_hex": result.hex() if isinstance(result, bytes) else None,
        "score": score,
        "depth": depth,
        "chain": chain,
        "parameters": parameters,
        "elapsed_seconds": round(time.perf_counter() - started_at, 6),
        "error": None,
    }


def _from_candidate(candidate: dict, depth: int, chain: list[str], started_at: float) -> dict:
    parameters = {key: value for key, value in candidate.items() if key not in {"result", "score", "method"}}
    method = candidate.get("method", chain[-1] if chain else "unknown")
    return _make_result(method, candidate.get("result", ""), candidate.get("score", 0.0), depth, chain, parameters, started_at)


def _error_result(method: str, error: Exception, depth: int, chain: list[str], started_at: float) -> dict:
    return {
        "method": method,
        "result": "",
        "result_bytes_hex": None,
        "score": 0.0,
        "depth": depth,
        "chain": chain + [method],
        "parameters": {},
        "elapsed_seconds": round(time.perf_counter() - started_at, 6),
        "error": f"{type(error).__name__}: {error}",
    }


def _deduplicate(results: list[dict]) -> list[dict]:
    unique = {}
    for result in results:
        key = (result.get("method"), result.get("result"), tuple(result.get("chain", [])))
        previous = unique.get(key)
        if previous is None or result.get("score", 0) > previous.get("score", 0):
            unique[key] = result
    return list(unique.values())
