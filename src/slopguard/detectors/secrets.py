"""SG005: Hardcoded Secret & API Key Detector."""

from __future__ import annotations

import re
from pathlib import Path

from slopguard.models import Finding, Severity

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("GitHub Fine-Grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Stripe Live Key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
]


def _mask_secret(token: str) -> str:
    if len(token) <= 10:
        return "***"
    return f"{token[:6]}...{token[-4:]}"


def detect_secrets(file_path: Path, rel_path: str, content: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()

    for idx, line in enumerate(lines, start=1):
        for label, pattern in SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                masked = _mask_secret(m.group(0))
                findings.append(
                    Finding(
                        rule_id="SG005",
                        title="Hardcoded Secret or API Key",
                        severity=Severity.CRITICAL,
                        category="Credential Leak",
                        file_path=rel_path,
                        line=idx,
                        column=m.start() + 1,
                        message=f"Potential {label} detected ({masked}).",
                        snippet=line.strip().replace(m.group(0), masked),
                        suggestion="Move credentials to environment variables or a secret manager and rotate the key.",
                    )
                )
    return findings
