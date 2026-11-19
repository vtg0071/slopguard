"""Markdown formatter for GitHub PR comments."""

from __future__ import annotations

from slopguard.models import ScanReport


def format_markdown(report: ScanReport) -> str:
    counts = report.counts_by_severity()
    status_emoji = "✅" if not report.findings else "🚨" if counts["critical"] or counts["high"] else "⚠️"
    lines = [
        f"## {status_emoji} SlopGuard Report — Grade **{report.grade}** (Slop Score: `{report.slop_score}/100`)",
        "",
        f"Scanned **{report.files_scanned}** file(s) in `{report.duration_ms:.1f}ms`.",
        "",
    ]
    if not report.findings:
        lines.append("No AI coding slop, phantom imports, or security issues detected.")
        return "\n".join(lines)

    lines.extend([
        "| Severity | Rule | Location | Issue |",
        "| :--- | :--- | :--- | :--- |",
    ])
    for f in report.findings:
        msg = f.message.replace("|", "\\|")
        lines.append(f"| `{f.severity.value.upper()}` | `{f.rule_id}` | `{f.file_path}:{f.line}` | {msg} |")
    return "\n".join(lines)
