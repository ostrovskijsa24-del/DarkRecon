from __future__ import annotations
import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules.crypto.analyzer import analyze_crypto  
from modules.crypto.output import print_probable_flags  


def run_crypto_analysis(
    data: str,
    recursive: bool = True,
    max_depth: int = 2,
    limit: int = 7,
) -> list[dict]:
    results = analyze_crypto(data, recursive=recursive, max_depth=max_depth)

    print("\n=== TOP PROBABLE FLAGS ===")
    print_probable_flags(results, limit=limit)

    # from modules.crypto.output import save_report
    # save_report(results, "results")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Temporary crypto module runner")
    parser.add_argument("data", nargs="?", help="Text to analyze. If omitted, input is requested.")
    parser.add_argument("--max-depth", type=int, default=2)
    parser.add_argument("--no-recursive", action="store_true")
    parser.add_argument("--limit", type=int, default=7)
    args = parser.parse_args()

    data = args.data if args.data is not None else input("Введите строку для анализа: ")
    run_crypto_analysis(
        data=data,
        recursive=not args.no_recursive,
        max_depth=args.max_depth,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
