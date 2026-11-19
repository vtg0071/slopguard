"""Rich ANSI terminal formatter for SlopGuard."""

from __future__ import annotations

import os
import sys

from slopguard import __version__
from slopguard.models import ScanReport, Severity


def _supports_color(no_color: bool = False) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"\033[{code}m{text}\033[0m"


def _severity_badge(sev: Severity, use_color: bool) -> str:
    colors = {
        Severity.CRITICAL: "1;97;41",
        Severity.HIGH: "1;91",
        Severity.MEDIUM: "1;93",
        Severity.LOW: "1;96",
    }
    label = f" {sev.value.upper():<8} " if sev == Severity.CRITICAL else f"{sev.value.upper():<8}"
    return _c(label, colors[sev], use_color)


def _score_bar(score: int, use_color: bool) -> str:
    filled = round(score / 5)
    bar = "█" * filled + "░" * (20 - filled)
    color = "1;92" if score <= 10 else "1;93" if score <= 40 else "1;91"
    return _c(f"[{bar}] {score}/100", color, use_color)


def format_terminal(report: ScanReport, no_color: bool = False) -> str:
    use_color = _supports_color(no_color)
    lines: list[str] = []

    header = _c(f"SlopGuard v{__version__}", "1;97", use_color) + _c(" — AI Coding Slop & Supply-Chain Scanner", "2", use_color)
    lines.append(header)
    lines.append(
        f"Target: {_c(report.target, '1', use_color)}  |  "
        f"Files: {report.files_scanned}  |  "
        f"Time: {report.duration_ms:.1f}ms"
    )
    lines.append(
        f"Slop Score: {_score_bar(report.slop_score, use_color)}  |  "
        f"Grade: {_c(report.grade, '1;97', use_color)}"
    )
    lines.append("")

    if not report.findings:
        lines.append(_c("✔ Zero AI slop detected. Ready to merge!", "1;92", use_color))
        return "\n".join(lines)

    for f in report.findings:
        loc = _c(f"{f.file_path}:{f.line}:{f.column}", "1;94", use_color)
        rule = _c(f"[{f.rule_id}]", "1;35", use_color)
        badge = _severity_badge(f.severity, use_color)
        lines.append(f"{badge} {rule} {loc} — {f.message}")
        if f.snippet:
            lines.append(f"         {_c('│', '2', use_color)} {_c(f.snippet, '2', use_color)}")
        if f.suggestion:
            lines.append(f"         {_c('↳ Fix:', '32', use_color)} {f.suggestion}")
        lines.append("")

    counts = report.counts_by_severity()
    summary = (
        f"Summary: {len(report.findings)} issue(s) — "
        f"{counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low"
    )
    lines.append(_c(summary, "1", use_color))
    return "\n".join(lines)
