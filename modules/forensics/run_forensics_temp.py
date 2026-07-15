from __future__ import annotations
import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.forensics.analyzer import analyze_forensics  
from modules.forensics.output import print_feed, print_full_report 


def resolve_input_path(user_input: str) -> Path:
    raw_path = Path(user_input).expanduser()
    search_places = _unique_paths([
        raw_path,
        Path.cwd() / raw_path,
        Path(__file__).resolve().parent / raw_path,
        PROJECT_ROOT / raw_path,
    ])

    for path in search_places:
        if path.is_file():
            return path.resolve()

    if len(raw_path.parts) == 1:
        matches = [path for path in PROJECT_ROOT.rglob(raw_path.name) if path.is_file()]
        if len(matches) == 1:
            return matches[0].resolve()
        if len(matches) > 1:
            print("Найдено несколько файлов с таким именем:")
            for number, path in enumerate(matches, start=1):
                print(f"{number}. {path}")
            raise FileNotFoundError("укажи более точный путь к файлу")

    checked = "\n".join(f"- {path}" for path in search_places)
    raise FileNotFoundError(f"файл не найден. Проверенные места:\n{checked}")


def _unique_paths(paths: list[Path]) -> list[Path]:
    unique = []
    seen = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path.absolute())
        if key not in seen:
            seen.add(key)
            unique.append(path)
    return unique


def main() -> None:
    parser = argparse.ArgumentParser(description="Temporary forensics runner")
    parser.add_argument("path", nargs="?", help="Path to file for analysis.")
    parser.add_argument("--chunk-size", type=int, default=1024)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--full-json", action="store_true")
    args = parser.parse_args()

    path = args.path if args.path else input("Введите путь к файлу: ")
    try:
        resolved_path = resolve_input_path(path)
    except FileNotFoundError as error:
        print(f"Ошибка: {error}")
        return

    result = analyze_forensics(resolved_path, chunk_size=args.chunk_size)

    print_feed(result, limit=args.limit)
    if args.full_json:
        print("\n=== FULL REPORT JSON ===")
        print_full_report(result)

    # from modules.forensics.output import save_report_json, save_report_txt
    # save_report_json(result, "results/forensics_report.json")
    # save_report_txt(result, "results/forensics_report.txt")


if __name__ == "__main__":
    main()
