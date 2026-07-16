"""
Вывод отчётов модуля Crypto.
"""
from __future__ import annotations

from pathlib import Path
from rich.markup import escape
from . import console

from modules.crypto.flags import split_probable_results, get_patterns, extract_flag_match


def print_and_save_report(results: list[dict], output_path: Path, flag_prefix: str = "", limit: int = 7) -> None:
    # 1. Спрашиваем бизнес-логику, кто в Топе (с учетом нашего префикса)
    selected, remaining = split_probable_results(results, limit, custom_prefix=flag_prefix)
    patterns = get_patterns(flag_prefix)
    
    # 2. Сохраняем текстовый отчет (отбрасывая то, что ушло в консоль)
    _save_results_txt(remaining, output_path)

    # 3. Рисуем красивый интерфейс в консоли
    if not selected:
        console.print("[yellow]Подходящих кандидатов не найдено.[/]")
        console.print(f"[dim]Текстовый отчет со всеми попытками сохранен:[/] {output_path}")
        return

    console.print(f"\n[bold cyan]═══ Показаны {len(selected)} наиболее вероятных флагов ═══[/]")
    for number, result in enumerate(selected, start=1):
        score = float(result.get("score", 0.0))
        chain = " -> ".join(result.get("chain", [])) or result.get("method", "unknown")
        safe_chain = escape(chain)

        if result.get("error"):
            safe_err = escape(str(result.get("error")))
            console.print(f"  [red]{number}. \\[[ERROR]\\][/red] [cyan]{safe_chain}[/]: {safe_err}")
        else:
            text = str(result.get("result", ""))
            match = extract_flag_match(text, patterns)
            preview = match or text.replace("\n", "\\n")
            candidate = preview if len(preview) <= 120 else preview[:117] + "..."
            
            console.print(f"  [green]{number}.[/] \\[[bold]{score:.4f}[/]\\] [cyan]{safe_chain}[/]: {escape(candidate)}")

    console.print(f"\n[dim]Остальные результаты ({len(remaining)} шт.) сохранены в:[/] [yellow]{output_path}[/]")


def _save_results_txt(results: list[dict], path: Path) -> None:
    """Внутренняя функция TUI для сохранения plain-text файла (без цветов)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    title = "Crypto Analysis Remaining Candidates"
    lines = [title, "=" * len(title), ""]
    
    if not results:
        lines.append("Остальных результатов нет.")
    else:
        for number, result in enumerate(results, start=1):
            method = result.get("method", "unknown")
            score = float(result.get("score", 0.0))
            chain = " -> ".join(result.get("chain", [])) or method
            
            if result.get("error"):
                lines.append(f"{number}. [{score:.4f}] {method} ({chain}) ERROR: {result.get('error')}")
            else:
                text = str(result.get("result", "")).replace("\n", "\\n")
                if len(text) > 240: text = text[:237] + "..."
                
                params = result.get("parameters", {})
                param_str = ", ".join(f"{k}={v.hex() if isinstance(v, bytes) else str(v)[:117]}" for k, v in params.items())
                suffix = f" params={param_str}" if param_str else ""
                
                lines.append(f"{number}. [{score:.4f}] {method} ({chain}){suffix}: {text}")

            lines.append(f"depth: {result.get('depth')}")
            lines.append(f"elapsed_seconds: {result.get('elapsed_seconds')}")
            if result.get("result_bytes_hex"):
                lines.append(f"result_bytes_hex: {result.get('result_bytes_hex')}")
            lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")