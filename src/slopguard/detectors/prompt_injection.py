"""SG006: Hidden Unicode (Trojan Source) & Prompt Injection Detector."""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path

from slopguard.models import Finding, Severity

BIDI_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}
# ZWNJ/ZWJ between two non-ASCII chars is legitimate (emoji sequences, Persian/Indic text);
# next to ASCII (identifiers, keywords) or a line edge it is a hiding trick.
HIDDEN_ZERO_WIDTH_RE = re.compile(r"\u200b|(?<![^\x00-\x7f])[\u200c\u200d]|[\u200c\u200d](?![^\x00-\x7f])")

PROMPT_INJECTION_RE = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:your\s+)?system\s+prompt"
    r"|you\s+are\s+now\s+in\s+developer\s+mode"
    r"|exfiltrate\s+(?:secrets|env|keys|tokens))",
    re.IGNORECASE,
)


def _iter_scannable_text_segments(file_path: Path, content: str) -> list[tuple[int, int, str]]:
    """For Python files, scan only real comments (avoiding string literal false positives)."""
    if file_path.suffix.lower() != ".py":
        return [(idx, 1, line) for idx, line in enumerate(content.splitlines(), start=1)]

    segments: list[tuple[int, int, str]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(content).readline):
            if tok.type == tokenize.COMMENT:
                segments.append((tok.start[0], tok.start[1] + 1, tok.string))
    except tokenize.TokenError:
        return [(idx, 1, line) for idx, line in enumerate(content.splitlines(), start=1)]
    return segments


def detect_prompt_injection(
    file_path: Path,
    rel_path: str,
    content: str,
    comments: list[tuple[int, int, str]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    # 1. Hidden Unicode / Trojan Source characters across all lines
    for idx, line in enumerate(lines, start=1):
        zw = HIDDEN_ZERO_WIDTH_RE.search(line)
        for col, ch in enumerate(line, start=1):
            if ch in BIDI_CHARS:
                findings.append(
                    Finding(
                        rule_id="SG006",
                        title="Hidden Unicode / Prompt Injection",
                        severity=Severity.CRITICAL,
                        category="Agent & Supply-Chain Security",
                        file_path=rel_path,
                        line=idx,
                        column=col,
                        message=f"Bidirectional Unicode override character (U+{ord(ch):04X}) detected (Trojan Source risk).",
                        snippet=repr(line.strip()),
                        suggestion="Remove hidden bidirectional control characters immediately.",
                    )
                )
                break
            if zw is not None and col - 1 == zw.start():
                findings.append(
                    Finding(
                        rule_id="SG006",
                        title="Hidden Unicode / Prompt Injection",
                        severity=Severity.HIGH,
                        category="Agent & Supply-Chain Security",
                        file_path=rel_path,
                        line=idx,
                        column=col,
                        message=f"Hidden zero-width Unicode character (U+{ord(ch):04X}) detected.",
                        snippet=repr(line.strip()),
                        suggestion="Strip invisible zero-width characters from source code.",
                    )
                )
                break

    # 2. Prompt injection phrases in comments / docs
    segs = comments if (comments is not None and file_path.suffix.lower() == ".py") else _iter_scannable_text_segments(file_path, content)
    for line_no, base_col, seg_text in segs:
        m = PROMPT_INJECTION_RE.search(seg_text)
        if m:
            findings.append(
                Finding(
                    rule_id="SG006",
                    title="Hidden Unicode / Prompt Injection",
                    severity=Severity.CRITICAL,
                    category="Agent & Supply-Chain Security",
                    file_path=rel_path,
                    line=line_no,
                    column=base_col + m.start(),
                    message=f"Suspicious agent prompt-injection pattern: '{m.group(0)}'.",
                    snippet=lines[line_no - 1].strip() if 0 < line_no <= len(lines) else seg_text.strip(),
                    suggestion="Remove instruction-hijack text targeting AI coding assistants.",
                )
            )

    return findings
