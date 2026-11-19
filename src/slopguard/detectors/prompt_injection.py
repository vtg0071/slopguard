"""SG006: Hidden Unicode (Trojan Source) & Prompt Injection Detector."""

from __future__ import annotations

import re
from pathlib import Path

from slopguard.models import Finding, Severity

BIDI_CHARS = {
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
    "\u2066", "\u2067", "\u2068", "\u2069",
}
ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d"}

PROMPT_INJECTION_RE = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:your\s+)?system\s+prompt"
    r"|you\s+are\s+now\s+in\s+developer\s+mode"
    r"|exfiltrate\s+(?:secrets|env|keys|tokens))",
    re.IGNORECASE,
)


def detect_prompt_injection(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
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
            if ch in ZERO_WIDTH_CHARS:
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

        m = PROMPT_INJECTION_RE.search(line)
        if m:
            findings.append(
                Finding(
                    rule_id="SG006",
                    title="Hidden Unicode / Prompt Injection",
                    severity=Severity.CRITICAL,
                    category="Agent & Supply-Chain Security",
                    file_path=rel_path,
                    line=idx,
                    column=m.start() + 1,
                    message=f"Suspicious agent prompt-injection pattern: '{m.group(0)}'.",
                    snippet=line.strip(),
                    suggestion="Remove instruction-hijack text targeting AI coding assistants.",
                )
            )

    return findings
