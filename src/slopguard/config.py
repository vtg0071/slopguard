"""Configuration loader for SlopGuard (zero external dependencies)."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from slopguard.models import Severity

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


DEFAULT_IGNORES = [
    ".git/**",
    ".hg/**",
    ".svn/**",
    ".venv/**",
    "venv/**",
    "env/**",
    "__pycache__/**",
    "*.pyc",
    "node_modules/**",
    "dist/**",
    "build/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    "*.min.js",
    "*.min.css",
]


@dataclass
class SlopGuardConfig:
    fail_on: Severity = Severity.HIGH
    ignore: list[str] = field(default_factory=lambda: list(DEFAULT_IGNORES))
    disabled_rules: set[str] = field(default_factory=set)
    extra_dependencies: set[str] = field(default_factory=set)
    max_file_size_bytes: int = 512_000

    def is_ignored(self, rel_path: str) -> bool:
        norm = rel_path.replace("\\", "/").lstrip("./")
        parts = norm.split("/")
        for pattern in self.ignore:
            pat = pattern.replace("\\", "/").lstrip("./")
            if fnmatch.fnmatch(norm, pat):
                return True
            if pat.endswith("/**"):
                prefix = pat[:-3]
                if norm == prefix or norm.startswith(prefix + "/"):
                    return True
            if any(fnmatch.fnmatch(part, pat) for part in parts):
                return True
        return False


def _strip_toml_comment(line: str) -> str:
    in_quote: str | None = None
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quote == '"':
            escaped = True
            continue
        if ch in ('"', "'"):
            if in_quote is None:
                in_quote = ch
            elif in_quote == ch:
                in_quote = None
        elif ch == "#" and in_quote is None:
            return line[:idx]
    return line


def _parse_simple_toml_fallback(text: str) -> dict[str, Any]:
    """Fallback TOML parser for Python 3.10 supporting multi-line arrays."""
    data: dict[str, Any] = {}
    section = data
    pending_key: str | None = None
    pending_buf: list[str] = []

    for raw_line in text.splitlines():
        line = _strip_toml_comment(raw_line).strip()
        if not line:
            continue

        if pending_key is not None:
            pending_buf.append(line)
            if "]" in line:
                joined = " ".join(pending_buf)
                inner = joined[joined.find("[") + 1 : joined.rfind("]")]
                section[pending_key] = [
                    m.group(1)
                    for m in re.finditer(r"""['"]([^'"]*)['"]""", inner)
                ]
                pending_key = None
                pending_buf = []
            continue

        if line.startswith("[") and line.endswith("]"):
            sec_name = line[1:-1].strip()
            cur = data
            for part in sec_name.split("."):
                cur = cur.setdefault(part, {})
            section = cur
            continue

        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                section[k] = v[1:-1]
            elif v.startswith("["):
                if "]" in v:
                    inner = v[1 : v.rfind("]")]
                    section[k] = [
                        m.group(1)
                        for m in re.finditer(r"""['"]([^'"]*)['"]""", inner)
                    ]
                else:
                    pending_key = k
                    pending_buf = [v]
    return data


def _read_toml(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if tomllib is not None:
        return tomllib.loads(raw)
    return _parse_simple_toml_fallback(raw)


def load_config(root: Path) -> SlopGuardConfig:
    cfg = SlopGuardConfig()
    slopguard_toml = root / ".slopguard.toml"
    pyproject_toml = root / "pyproject.toml"

    raw_section: dict[str, Any] = {}
    if slopguard_toml.is_file():
        raw_section = _read_toml(slopguard_toml)
    elif pyproject_toml.is_file():
        parsed = _read_toml(pyproject_toml)
        raw_section = parsed.get("tool", {}).get("slopguard", {})

    if not raw_section:
        return cfg

    if "fail-on" in raw_section or "fail_on" in raw_section:
        val = str(raw_section.get("fail-on", raw_section.get("fail_on", "high"))).lower()
        if val in {s.value for s in Severity}:
            cfg.fail_on = Severity(val)

    if "ignore" in raw_section and isinstance(raw_section["ignore"], list):
        cfg.ignore = list(DEFAULT_IGNORES) + [str(x) for x in raw_section["ignore"]]

    if "disable" in raw_section and isinstance(raw_section["disable"], list):
        cfg.disabled_rules = {str(x).upper() for x in raw_section["disable"]}

    if "extra-dependencies" in raw_section or "extra_dependencies" in raw_section:
        deps = raw_section.get("extra-dependencies", raw_section.get("extra_dependencies", []))
        if isinstance(deps, list):
            cfg.extra_dependencies = {str(x).lower().replace("-", "_") for x in deps}

    return cfg
